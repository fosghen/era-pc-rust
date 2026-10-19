use crate::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Value {
    Number(f64),
    Text(String),
    Bool(bool),
}
impl Value {
    pub fn number(&self) -> Result<f64> {
        match self {
            Self::Number(n) => Ok(*n),
            _ => Err(format!("Expected number, got {self:?}")),
        }
    }
    pub fn boolean(&self) -> Result<bool> {
        match self {
            Self::Bool(b) => Ok(*b),
            Self::Number(n) => Ok(*n != 0.0),
            _ => Err("Expected logical value".into()),
        }
    }
    pub fn text(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::Number(n) => n.to_string(),
            Self::Bool(b) => b.to_string(),
        }
    }
}
#[derive(Clone, Debug)]
pub enum Expr {
    Literal(Value),
    Var(String),
    Unary(String, Box<Expr>),
    Binary(String, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
    Tab(String),
    Column(usize),
}
#[derive(Clone, Debug, PartialEq)]
enum Token {
    Number(f64),
    Text(String),
    Name(String),
    Op(String),
    Left,
    Right,
    Comma,
    Column(usize),
    Tab(String),
    End,
}

pub fn split_top(s: &str, separator: char) -> Result<Vec<String>> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quote = None;
    for (i, c) in s.char_indices() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            '(' | '[' => depth += 1,
            ')' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err("Unbalanced delimiters".into());
                }
            }
            _ if c == separator && depth == 0 => {
                parts.push(s[start..i].trim().to_string());
                start = i + c.len_utf8();
            }
            _ => {}
        }
    }
    if quote.is_some() || depth != 0 {
        return Err("Unclosed string or parentheses".into());
    }
    parts.push(s[start..].trim().to_string());
    Ok(parts)
}
fn lex(s: &str) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let c = s[i..].chars().next().unwrap();
        if c.is_whitespace() {
            i += c.len_utf8();
            continue;
        }
        if c == '\'' || c == '"' {
            let q = c;
            i += 1;
            let mut value = String::new();
            let mut closed = false;
            while i < s.len() {
                let c = s[i..].chars().next().unwrap();
                i += c.len_utf8();
                if c == q {
                    if s[i..].starts_with(q) {
                        value.push(q);
                        i += 1;
                    } else {
                        closed = true;
                        break;
                    }
                } else {
                    value.push(c);
                }
            }
            if !closed {
                return Err("Unclosed string".into());
            }
            tokens.push(Token::Text(value));
            continue;
        }
        let lower = s[i..].to_lowercase();
        let mut matched = false;
        for (raw, op) in [
            (".and.", "and"),
            (".or.", "or"),
            (".not.", "not"),
            (".или.", "or"),
            (".и.", "and"),
            (".t.", "true"),
            (".f.", "false"),
        ] {
            if lower.starts_with(raw) {
                tokens.push(Token::Op(op.into()));
                i += raw.len();
                matched = true;
                break;
            }
        }
        if matched {
            continue;
        }
        if c.is_ascii_digit()
            || (c == '.'
                && s[i + 1..]
                    .chars()
                    .next()
                    .is_some_and(|n| n.is_ascii_digit()))
        {
            let start = i;
            let bytes = s.as_bytes();
            while i < s.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            // A dot before AND/OR belongs to a logical operator, not this number.
            if i < s.len()
                && bytes[i] == b'.'
                && !s[i..].to_lowercase().starts_with(".and.")
                && !s[i..].to_lowercase().starts_with(".or.")
                && !s[i..].to_lowercase().starts_with(".и.")
                && !s[i..].to_lowercase().starts_with(".или.")
            {
                i += 1;
                while i < s.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            if i < s.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
                i += 1;
                if i < s.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
                    i += 1;
                }
                while i < s.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
            }
            tokens.push(Token::Number(
                s[start..i]
                    .parse()
                    .map_err(|_| format!("Invalid number {}", &s[start..i]))?,
            ));
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let start = i;
            i += c.len_utf8();
            while i < s.len() {
                let c = s[i..].chars().next().unwrap();
                if c.is_alphanumeric() || c == '_' {
                    i += c.len_utf8();
                } else if c == '.'
                    && ![".and.", ".or.", ".not.", ".и.", ".или."]
                        .iter()
                        .any(|op| s[i..].to_lowercase().starts_with(op))
                    && s[i + 1..]
                        .chars()
                        .next()
                        .is_some_and(|ch| ch.is_alphabetic() || ch == '_')
                {
                    // A project field such as ngor.kno_. The host must explicitly supply its value.
                    i += 1;
                } else {
                    break;
                }
            }
            let name = s[start..i].to_lowercase();
            // Bare logical words are resolved by the parser, not the lexer:
            // Or is also the oxygen-content variable in recovered fuel formulas.
            let rest = s[i..].trim_start();
            if name == "tab" && rest.starts_with('(') {
                i = s.len() - rest.len() + 1;
                let start = i;
                let mut depth = 1;
                let mut quote = None;
                while i < s.len() {
                    let c = s[i..].chars().next().unwrap();
                    if let Some(q) = quote {
                        if c == q {
                            quote = None;
                        }
                    } else if c == '\'' || c == '"' {
                        quote = Some(c);
                    } else if c == '(' {
                        depth += 1;
                    } else if c == ')' {
                        depth -= 1;
                        if depth == 0 {
                            break;
                        }
                    }
                    i += c.len_utf8();
                }
                if depth != 0 {
                    return Err("Unclosed TAB call".into());
                }
                tokens.push(Token::Tab(s[start..i].to_string()));
                i += 1;
            } else {
                tokens.push(Token::Name(name));
            }
            continue;
        }
        if c == '[' {
            let end = s[i + 1..].find(']').ok_or("Unclosed column reference")? + i + 1;
            tokens.push(Token::Column(
                s[i + 1..end]
                    .trim()
                    .parse()
                    .map_err(|_| "Invalid column number")?,
            ));
            i = end + 1;
            continue;
        }
        let t = match c {
            '(' => Token::Left,
            ')' => Token::Right,
            ',' => Token::Comma,
            '+' | '-' | '*' | '/' | '^' | '=' | '<' | '>' | '!' | '#' | '$' | '%' => {
                let mut op = c.to_string();
                let rest = &s[i + c.len_utf8()..];
                if ((c == '<' || c == '>' || c == '!' || c == '=') && rest.starts_with('='))
                    || (c == '<' && rest.starts_with('>'))
                    || (c == '*' && rest.starts_with('*'))
                {
                    op.push(rest.chars().next().unwrap());
                    i += 1;
                }
                Token::Op(op)
            }
            _ => return Err(format!("Unsupported character {c:?}")),
        };
        tokens.push(t);
        i += c.len_utf8();
    }
    tokens.push(Token::End);
    Ok(tokens)
}
pub fn parse(s: &str) -> Result<Expr> {
    let mut p = Parser {
        tokens: lex(s)?,
        index: 0,
    };
    let expr = p.expression(0)?;
    if p.tokens[p.index] != Token::End {
        return Err(format!("Unexpected token {:?}", p.tokens[p.index]));
    }
    Ok(expr)
}
struct Parser {
    tokens: Vec<Token>,
    index: usize,
}
impl Parser {
    fn expression(&mut self, min: u8) -> Result<Expr> {
        let t = self.tokens[self.index].clone();
        self.index += 1;
        let mut lhs = match t {
            Token::Number(v) => Expr::Literal(Value::Number(v)),
            Token::Text(v) => Expr::Literal(Value::Text(v)),
            Token::Column(v) => Expr::Column(v),
            Token::Tab(raw) => Expr::Tab(raw),
            Token::Op(ref op) if op == "true" || op == "false" => {
                Expr::Literal(Value::Bool(op == "true"))
            }
            Token::Op(ref op) if ["-", "+", "!", "not"].contains(&op.as_str()) => {
                let priority = if op == "!" || op == "not" { 3 } else { 6 };
                Expr::Unary(op.clone(), Box::new(self.expression(priority)?))
            }
            Token::Name(ref name) if name == "not" || name == "не" => {
                Expr::Unary("not".into(), Box::new(self.expression(3)?))
            }
            Token::Name(name) => {
                if self.tokens[self.index] == Token::Left {
                    self.index += 1;
                    let mut args = Vec::new();
                    if self.tokens[self.index] != Token::Right {
                        loop {
                            args.push(self.expression(0)?);
                            if self.tokens[self.index] != Token::Comma {
                                break;
                            }
                            self.index += 1;
                        }
                    }
                    if self.tokens[self.index] != Token::Right {
                        return Err("Expected closing parenthesis".into());
                    }
                    self.index += 1;
                    Expr::Call(name, args)
                } else {
                    Expr::Var(name)
                }
            }
            Token::Left => {
                let v = self.expression(0)?;
                if self.tokens[self.index] != Token::Right {
                    return Err("Expected closing parenthesis".into());
                }
                self.index += 1;
                v
            }
            _ => return Err(format!("Expected expression, got {t:?}")),
        };
        loop {
            let op = match &self.tokens[self.index] {
                Token::Op(op) => op.as_str(),
                Token::Name(name) => match name.as_str() {
                    "and" | "и" => "and",
                    "or" | "или" => "or",
                    _ => break,
                },
                _ => break,
            };
            let priority = match op {
                "or" => 1,
                "and" => 2,
                "=" | "==" | "<>" | "!=" | "#" | "<" | ">" | "<=" | ">=" | "$" => 3,
                "+" | "-" => 4,
                "*" | "/" | "%" => 5,
                "^" | "**" => 7,
                _ => break,
            };
            if priority < min {
                break;
            }
            let op = op.to_string();
            self.index += 1;
            let rhs = self.expression(if priority == 7 {
                priority
            } else {
                priority + 1
            })?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }
}

#[derive(Clone, Debug)]
pub enum Statement {
    Empty,
    Eval(Expr),
    Assign(Vec<Target>, Expr),
    If(Expr, Box<Statement>, Option<Box<Statement>>),
    Goto(Expr),
    End,
    Dimension(Vec<Target>),
}
#[derive(Clone, Debug)]
pub struct Target {
    pub name: String,
    pub indices: Vec<Expr>,
}
fn targets(s: &str) -> Result<Vec<Target>> {
    split_top(s, ',')?
        .iter()
        .map(|part| match parse(part)? {
            Expr::Var(name) if !name.contains('.') => Ok(Target {
                name,
                indices: vec![],
            }),
            Expr::Call(name, indices)
                if !name.contains('.') && (1..=2).contains(&indices.len()) =>
            {
                Ok(Target { name, indices })
            }
            _ => Err("Target must be a variable or array element".into()),
        })
        .collect()
}
pub fn statement(s: &str) -> Result<Statement> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Statement::Empty);
    }
    let low = s.to_lowercase();
    if low == "конец" {
        return Ok(Statement::End);
    }
    if low.starts_with("шаг ") {
        return Ok(Statement::Goto(parse(s["шаг ".len()..].trim())?));
    }
    if low.starts_with("если ") {
        let parts = split_top(&s["если ".len()..], ',')?;
        if parts.len() < 2 || parts.len() > 3 {
            return Err("ЕСЛИ requires condition, branch[, alternative]".into());
        }
        return Ok(Statement::If(
            parse(&parts[0])?,
            Box::new(statement(&parts[1])?),
            if parts.len() == 3 {
                Some(Box::new(statement(&parts[2])?))
            } else {
                None
            },
        ));
    }
    if low.starts_with("store ") {
        let pos = low.find(" to ").ok_or("STORE requires TO")?;
        let value = parse(&s[6..pos])?;
        return Ok(Statement::Assign(targets(&s[pos + 4..])?, value));
    }
    if low.starts_with("dimension ") {
        let arrays = targets(&s[10..])?;
        if arrays.iter().any(|t| t.indices.is_empty()) {
            return Err("DIMENSION target must include array dimensions".into());
        }
        return Ok(Statement::Dimension(arrays));
    }
    // A plain name list before '=' is assignment; comparisons remain expressions.
    let parts = split_top(s, '=')?;
    if parts.len() == 2 {
        if let Ok(names) = targets(&parts[0]) {
            return Ok(Statement::Assign(names, parse(&parts[1])?));
        }
    }
    Ok(Statement::Eval(parse(s)?))
}
