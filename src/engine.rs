use crate::{
    data::{table_id, Database, Row},
    expr::{self, Expr, Statement, Value},
    Result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize)]
pub struct Scenario {
    pub method: String,
    #[serde(default)]
    pub inputs: BTreeMap<String, Value>,
    /// Line-specific input queues let a source loop request different values.
    #[serde(default)]
    pub prompts: BTreeMap<usize, Vec<Value>>,
    /// Interactive TAB choices are explicit 1-based row numbers within a table/dictionary.
    #[serde(default)]
    pub selections: BTreeMap<usize, Vec<usize>>,
    #[serde(default)]
    pub initial: BTreeMap<String, Value>,
    #[serde(default)]
    pub trace: bool,
    #[serde(default = "default_limit")]
    pub max_steps: usize,
}
fn default_limit() -> usize {
    100_000
}
impl Default for Scenario {
    fn default() -> Self {
        Self {
            method: String::new(),
            inputs: BTreeMap::new(),
            prompts: BTreeMap::new(),
            selections: BTreeMap::new(),
            initial: BTreeMap::new(),
            trace: false,
            max_steps: default_limit(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct CompiledRow {
    pub source: Row,
    pub statement: Result<Statement>,
}
#[derive(Clone, Debug)]
pub struct Program {
    pub method: String,
    pub rows: Vec<CompiledRow>,
    pub labels: BTreeMap<usize, usize>,
}
impl Program {
    pub fn compile(method: &str, rows: &[Row]) -> Result<Self> {
        if rows.len() == 1 {
            return Err(format!(
                "Method {method} has a one-row placeholder, not a recovered algorithm"
            ));
        }
        let mut labels = BTreeMap::new();
        for (i, row) in rows.iter().enumerate() {
            if let Some(label) = row.label.filter(|n| *n != 0) {
                if labels.insert(label, i).is_some() {
                    return Err(format!("Ambiguous duplicate label {label}"));
                }
            }
        }
        Ok(Self {
            method: method.into(),
            rows: rows
                .iter()
                .map(|r| CompiledRow {
                    source: r.clone(),
                    statement: expr::statement(&r.formula),
                })
                .collect(),
            labels,
        })
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Trace {
    pub line: usize,
    pub record: usize,
    pub variable: String,
    pub value: Value,
}
#[derive(Clone, Debug, Serialize)]
pub struct OutputWrite {
    pub line: usize,
    pub pollutant: String,
    pub field: String,
    pub value: f64,
}
#[derive(Debug, Serialize)]
pub struct RunResult {
    pub method: String,
    pub steps: usize,
    pub variables: BTreeMap<String, Value>,
    pub writes: Vec<OutputWrite>,
    pub trace: Vec<Trace>,
    pub notes: Vec<String>,
}
enum Flow {
    Next,
    Jump(usize),
    End,
    Value(Value),
}
pub struct Runtime<'a> {
    db: &'a Database,
    method: String,
    pub variables: BTreeMap<String, Value>,
    scenario: Scenario,
    line: usize,
    selection_cursors: BTreeMap<usize, usize>,
    prompt_cursors: BTreeMap<usize, usize>,
    arrays: BTreeMap<String, (usize, usize, Vec<Value>)>,
    table_context: Option<Vec<Value>>,
    pub writes: Vec<OutputWrite>,
    notes: Vec<String>,
}
impl<'a> Runtime<'a> {
    pub fn new(db: &'a Database, scenario: Scenario) -> Self {
        let mut variables = BTreeMap::new();
        for (k, v) in [
            ("_off_", 0.),
            ("_on_", 1.),
            ("_only_", 2.),
            ("_step_", 1.),
            ("_prot_", 0.),
            ("_print_", 1.),
            ("_val_", 1.),
            ("_kolv_", 1.),
            ("_askitogo", 0.),
            ("_err_", 0.),
            ("_nvib_", 0.),
            ("_row_", 0.),
            ("_col_", 0.),
            ("_m_", 0.),
            ("_g_", 0.),
        ] {
            variables.insert(k.into(), Value::Number(v));
        }
        for k in ["_kod_", "_name_", "_v_"] {
            variables.insert(k.into(), Value::Text(String::new()));
        }
        for (k, v) in &scenario.initial {
            variables.insert(k.to_lowercase(), v.clone());
        }
        let mut arrays = BTreeMap::new();
        for name in ["_m1_", "_m2_", "_m3_"] {
            // Default FoxPro array initialization; algorithms explicitly STORE
            // numeric or textual values before using those elements.
            arrays.insert(name.into(), (50, 2, vec![Value::Bool(false); 100]));
        }
        Self {
            db,
            method: scenario.method.clone(),
            variables,
            scenario,
            line: 0,
            selection_cursors: BTreeMap::new(),
            prompt_cursors: BTreeMap::new(),
            arrays,
            table_context: None,
            writes: Vec::new(),
            notes: Vec::new(),
        }
    }
    fn get(&self, name: &str) -> Result<Value> {
        self.variables
            .get(name)
            .cloned()
            .ok_or_else(|| format!("Undefined variable {name}"))
    }
    fn put(&mut self, name: &str, v: Value) -> Result<()> {
        if ["_off_", "_on_", "_only_"].contains(&name) {
            return Err(format!("Cannot assign system constant {name}"));
        }
        if let Value::Number(n) = v {
            if !n.is_finite() {
                return Err(format!("Non-finite value for {name}"));
            }
        }
        if name == "_m_" || name == "_g_" {
            let pollutant = self.get("_v_")?.text();
            if pollutant.is_empty() {
                return Err("Output without pollutant _V_".into());
            }
            self.writes.push(OutputWrite {
                line: self.line,
                pollutant,
                field: name.into(),
                value: v.number()?,
            });
        }
        self.variables.insert(name.into(), v);
        Ok(())
    }
    pub fn eval(&mut self, e: &Expr) -> Result<Value> {
        let v = match e {
            Expr::Literal(v) => v.clone(),
            Expr::Var(n) => self.get(n)?,
            Expr::Column(n) => self
                .table_context
                .as_ref()
                .and_then(|v| n.checked_sub(1).and_then(|i| v.get(i)))
                .cloned()
                .ok_or("Column reference outside a TAB search")?,
            Expr::Tab(raw) => self.tab(raw)?,
            Expr::Unary(op, x) => {
                let v = self.eval(x)?;
                match op.as_str() {
                    "-" => Value::Number(-v.number()?),
                    "+" => Value::Number(v.number()?),
                    _ => Value::Bool(!v.boolean()?),
                }
            }
            Expr::Binary(op, a, b) => {
                let left = self.eval(a)?;
                if op == "and" && !left.boolean()? {
                    return Ok(Value::Bool(false));
                }
                if op == "or" && left.boolean()? {
                    return Ok(Value::Bool(true));
                }
                let right = self.eval(b)?;
                match op.as_str() {
                    "and" | "or" => Value::Bool(right.boolean()?),
                    "+" if matches!((&left, &right), (Value::Text(_), Value::Text(_))) => {
                        Value::Text(left.text() + &right.text())
                    }
                    "-" if matches!((&left, &right), (Value::Text(_), Value::Text(_))) => {
                        let l = left.text();
                        Value::Text(
                            l.trim_end().to_string()
                                + &right.text()
                                + &" ".repeat(l.len() - l.trim_end().len()),
                        )
                    }
                    "+" => Value::Number(left.number()? + right.number()?),
                    "-" => Value::Number(left.number()? - right.number()?),
                    "*" => Value::Number(left.number()? * right.number()?),
                    "/" => {
                        let n = right.number()?;
                        if n == 0. {
                            return Err("Division by zero".into());
                        }
                        Value::Number(left.number()? / n)
                    }
                    "%" => Value::Number(left.number()? % right.number()?),
                    "^" | "**" => Value::Number(left.number()?.powf(right.number()?)),
                    "$" => Value::Bool(right.text().contains(&left.text())),
                    "=" | "==" | "<>" | "!=" | "#" | "<" | ">" | "<=" | ">=" => {
                        let cmp = match (&left, &right) {
                            (Value::Number(a), Value::Number(b)) => a.partial_cmp(b),
                            (Value::Text(a), Value::Text(b)) => Some(a.cmp(b)),
                            (Value::Bool(a), Value::Bool(b)) => Some(a.cmp(b)),
                            _ => return Err("Comparison of incompatible types".into()),
                        }
                        .ok_or("Non-finite comparison")?;
                        let equal = if op == "=" {
                            match (&left, &right) {
                                (Value::Text(a), Value::Text(b)) => {
                                    a.trim_end().starts_with(b.trim_end())
                                }
                                _ => cmp.is_eq(),
                            }
                        } else {
                            cmp.is_eq()
                        };
                        Value::Bool(match op.as_str() {
                            "=" | "==" => equal,
                            "<>" | "!=" | "#" => !cmp.is_eq(),
                            "<" => cmp.is_lt(),
                            ">" => cmp.is_gt(),
                            "<=" => !cmp.is_gt(),
                            _ => !cmp.is_lt(),
                        })
                    }
                    _ => return Err(format!("Unsupported operator {op}")),
                }
            }
            Expr::Call(name, args) => {
                if name == "iif" {
                    if args.len() != 3 {
                        return Err("IIF needs three arguments".into());
                    }
                    let cond = self.eval(&args[0])?.boolean()?;
                    return self.eval(&args[if cond { 1 } else { 2 }]);
                }
                if name == "type" {
                    if args.len() != 1 {
                        return Err("TYPE needs one argument".into());
                    }
                    let key = self.eval(&args[0])?.text().to_lowercase();
                    return Ok(Value::Text(
                        match self.variables.get(&key) {
                            Some(Value::Number(_)) => "N",
                            Some(Value::Text(_)) => "C",
                            Some(Value::Bool(_)) => "L",
                            None => "U",
                        }
                        .into(),
                    ));
                }
                let values: Vec<Value> =
                    args.iter().map(|a| self.eval(a)).collect::<Result<_>>()?;
                if self.arrays.contains_key(name) {
                    let (nr, nc, data) = &self.arrays[name];
                    return Ok(data[array_offset(&values, *nr, *nc)?].clone());
                }
                if name == "_asum" || name == "_amax" {
                    return self.array_aggregate(name, &values);
                }
                self.call(name, &values)?
            }
        };
        if let Value::Number(n) = v {
            if !n.is_finite() {
                return Err("Non-finite arithmetic result".into());
            }
        }
        Ok(v)
    }
    fn call(&mut self, name: &str, args: &[Value]) -> Result<Value> {
        let a = |i: usize| {
            args.get(i)
                .ok_or_else(|| format!("Missing argument for {name}"))
        };
        let number = |i: usize| a(i)?.number();
        let text = |i: usize| -> Result<String> { Ok(a(i)?.text()) };
        let v = match name {
            "abs" => Value::Number(number(0)?.abs()),
            "sqrt" => Value::Number(number(0)?.sqrt()),
            "exp" => Value::Number(number(0)?.exp()),
            "log" => Value::Number(number(0)?.ln()),
            "log10" => Value::Number(number(0)?.log10()),
            "sin" => Value::Number(number(0)?.sin()),
            "cos" => Value::Number(number(0)?.cos()),
            "int" => Value::Number(number(0)?.trunc()),
            "round" => {
                let p = 10f64.powf(number(1)?);
                Value::Number((number(0)? * p).round() / p)
            }
            "min" | "max" => {
                if args.is_empty() {
                    return Err("MIN/MAX requires arguments".into());
                }
                Value::Number(
                    args.iter()
                        .map(Value::number)
                        .collect::<Result<Vec<_>>>()?
                        .into_iter()
                        .reduce(if name == "min" { f64::min } else { f64::max })
                        .unwrap(),
                )
            }
            "val" => {
                let s = text(0)?;
                let s = s.trim_start();
                let mut end = s.len();
                let n = loop {
                    if end == 0 {
                        break 0.;
                    }
                    if let Ok(n) = s[..end].parse::<f64>() {
                        break n;
                    }
                    end = s[..end].char_indices().last().unwrap().0;
                };
                Value::Number(n)
            }
            "empty" => Value::Bool(match a(0)? {
                Value::Text(s) => s.trim().is_empty(),
                Value::Number(n) => *n == 0.,
                Value::Bool(b) => !*b,
            }),
            "lower" | "textdn" => Value::Text(text(0)?.to_lowercase()),
            "upper" | "textup" => Value::Text(text(0)?.to_uppercase()),
            "alltrim" | "allt" => Value::Text(text(0)?.trim().into()),
            "ltrim" => Value::Text(text(0)?.trim_start().into()),
            "rtrim" => Value::Text(text(0)?.trim_end().into()),
            "len" => Value::Number(text(0)?.chars().count() as f64),
            "left" => Value::Text(
                text(0)?
                    .chars()
                    .take(nonnegative_index(number(1)?)?)
                    .collect(),
            ),
            "right" => {
                let s = text(0)?;
                let n = nonnegative_index(number(1)?)?;
                Value::Text(
                    s.chars()
                        .skip(s.chars().count().saturating_sub(n))
                        .collect(),
                )
            }
            "substr" | "substri" => {
                let s = text(0)?;
                let start = positive_index(number(1)?)?;
                let count = if args.len() > 2 {
                    nonnegative_index(number(2)?)?
                } else {
                    s.chars().count()
                };
                Value::Text(s.chars().skip(start).take(count).collect())
            }
            "inlist" => {
                let first = a(0)?;
                Value::Bool(args[1..].contains(first))
            }
            "str" | "lstr" => {
                let decimals = if args.len() > 2 {
                    nonnegative_index(number(2)?)?
                } else {
                    0
                };
                if decimals > 15 {
                    return Err("Excessive STR precision".into());
                }
                let s = format!("{:.*}", decimals, number(0)?);
                let width = if args.len() > 1 {
                    nonnegative_index(number(1)?)?
                } else {
                    10
                };
                if width > 1000 {
                    return Err("Excessive STR width".into());
                }
                Value::Text(if name == "lstr" {
                    s
                } else {
                    format!("{s:>width$}")
                })
            }
            "pitog" | "pitog_iz" => {
                self.notes.push(format!(
                    "line {}: {name} report rendering omitted; numeric output writes retained",
                    self.line
                ));
                Value::Number(0.)
            }
            // Host callbacks cannot safely be guessed from their names.
            _ => {
                return Err(format!(
                    "Unimplemented function {name}; requires recovery or host integration"
                ))
            }
        };
        Ok(v)
    }
    fn execute(&mut self, s: &Statement) -> Result<Flow> {
        match s {
            Statement::Empty => Ok(Flow::Next),
            Statement::End => Ok(Flow::End),
            Statement::Goto(n) => Ok(Flow::Jump(nonnegative_index(self.eval(n)?.number()?)?)),
            Statement::Eval(e) => Ok(Flow::Value(self.eval(e)?)),
            Statement::Assign(names, e) => {
                let value = self.eval(e)?;
                for target in names {
                    let indices = target
                        .indices
                        .iter()
                        .map(|e| self.eval(e))
                        .collect::<Result<Vec<_>>>()?;
                    if let Some((nr, nc, data)) = self.arrays.get_mut(&target.name) {
                        if indices.is_empty() {
                            // FoxPro SET COMPATIBLE OFF: assign to every element.
                            data.fill(value.clone());
                        } else {
                            let offset = array_offset(&indices, *nr, *nc)?;
                            data[offset] = value.clone();
                        }
                    } else if indices.is_empty() {
                        self.put(&target.name, value.clone())?;
                    } else {
                        return Err("Unknown array".into());
                    }
                }
                Ok(Flow::Next)
            }
            Statement::If(cond, yes, no) => {
                if self.eval(cond)?.boolean()? {
                    self.execute(yes)
                } else if let Some(no) = no {
                    self.execute(no)
                } else {
                    Ok(Flow::Next)
                }
            }
            Statement::Dimension(targets) => {
                for target in targets {
                    let name = &target.name;
                    if self.variables.contains_key(name) {
                        return Err("Array name conflicts with an existing variable".into());
                    }
                    let v = target
                        .indices
                        .iter()
                        .map(|a| self.eval(a))
                        .collect::<Result<Vec<_>>>()?;
                    let (r, c) = if v.len() == 1 {
                        (positive_index(v[0].number()?)?, 0)
                    } else {
                        indices(&v)?
                    };
                    let count = (r + 1)
                        .checked_mul(c + 1)
                        .filter(|n| *n <= 1_000_000)
                        .ok_or("Array too large")?;
                    // Redimensioning preserves values by linear element number.
                    let array = self
                        .arrays
                        .entry(name.clone())
                        .or_insert_with(|| (0, 0, Vec::new()));
                    array.0 = r + 1;
                    array.1 = c + 1;
                    array.2.resize(count, Value::Bool(false));
                }
                Ok(Flow::Next)
            }
        }
    }
    fn array_aggregate(&self, name: &str, args: &[Value]) -> Result<Value> {
        if args.len() != 5 {
            return Err("Array aggregate requires five arguments".into());
        }
        let Value::Text(array) = &args[0] else {
            return Err("Array aggregate requires an array name string".into());
        };
        let (nr, nc, data) = self
            .arrays
            .get(&array.to_lowercase())
            .ok_or("Unknown array")?;
        let row = nonnegative_index(args[1].number()?)?;
        let col = nonnegative_index(args[2].number()?)?;
        let first = positive_index(args[3].number()?)?;
        let last = positive_index(args[4].number()?)?;
        if first > last
            || (row > 0 && (row > *nr || last >= *nc))
            || (row == 0 && (col == 0 || col > *nc || last >= *nr))
        {
            return Err("Array aggregate range out of bounds".into());
        }
        let mut result = if name == "_amax" {
            f64::NEG_INFINITY
        } else {
            0.
        };
        for index in first..=last {
            let offset = if row > 0 {
                (row - 1) * nc + index
            } else {
                index * nc + col - 1
            };
            let value = data[offset].number()?;
            result = if name == "_amax" {
                result.max(value)
            } else {
                result + value
            };
        }
        if !result.is_finite() {
            return Err("Non-finite array aggregate".into());
        }
        Ok(Value::Number(result))
    }
    pub fn run(mut self, program: &Program) -> Result<RunResult> {
        if self.method != program.method {
            return Err("Scenario method does not match program".into());
        }
        for key in self.scenario.initial.keys() {
            if ["_toch_", "_mint_"].contains(&key.to_lowercase().as_str()) {
                return Err(
                    "ERA adaptive rounding is not implemented; use explicit raw-f64 mode".into(),
                );
            }
            if ["_on_", "_off_", "_only_"].contains(&key.to_lowercase().as_str()) {
                return Err("Cannot override system constants".into());
            }
        }
        let mut pc = 0;
        let mut steps = 0;
        let mut trace = Vec::new();
        while pc < program.rows.len() {
            steps += 1;
            if steps > self.scenario.max_steps {
                return Err(format!(
                    "Step limit {} exceeded at line {}",
                    self.scenario.max_steps, self.line
                ));
            }
            let row = &program.rows[pc];
            self.line = row.source.line;
            let name = row.source.variable.to_lowercase();
            let action = (|| -> Result<Flow> {
                let statement = row.statement.as_ref().map_err(Clone::clone)?;
                if matches!(statement, Statement::Empty) && !name.is_empty() {
                    let cursor = self.prompt_cursors.entry(self.line).or_default();
                    let supplied = if let Some(queue) = self.scenario.prompts.get(&self.line) {
                        let v = queue.get(*cursor).cloned().ok_or("Input queue exhausted")?;
                        *cursor += 1;
                        Some(v)
                    } else {
                        self.scenario
                            .inputs
                            .iter()
                            .find(|(k, _)| k.to_lowercase() == name)
                            .map(|(_, v)| v.clone())
                    };
                    if let Some(value) = supplied {
                        self.put(&name, value)?;
                    } else if !self.variables.contains_key(&name) {
                        return Err(format!(
                            "Input required: {name} ({})",
                            row.source.description
                        ));
                    }
                    return Ok(Flow::Next);
                }
                // A destination variable is initialized to numeric zero by the documented DSL.
                if !name.is_empty() {
                    self.variables
                        .entry(name.clone())
                        .or_insert(Value::Number(0.));
                }
                if self.variables.get("_val_") == Some(&Value::Number(0.))
                    && !name.is_empty()
                    && name != "_val_"
                {
                    return Err("_Val_=0 presentation mode requires host semantics".into());
                }
                let action = self.execute(statement)?;
                if let Flow::Value(ref value) = action {
                    if !name.is_empty() {
                        let value = if let Some(queue) = self.scenario.prompts.get(&self.line) {
                            let cursor = self.prompt_cursors.entry(self.line).or_default();
                            let supplied =
                                queue.get(*cursor).cloned().ok_or("Input queue exhausted")?;
                            *cursor += 1;
                            supplied
                        } else {
                            value.clone()
                        };
                        self.put(&name, value)?;
                    }
                }
                Ok(action)
            })()
            .map_err(|e| {
                format!(
                    "method {}, line {}, DBF #{}: {e}",
                    self.method, self.line, row.source.record
                )
            })?;
            if self.scenario.trace && !name.is_empty() {
                if let Some(value) = self.variables.get(&name) {
                    trace.push(Trace {
                        line: self.line,
                        record: row.source.record,
                        variable: name,
                        value: value.clone(),
                    });
                }
            }
            match action {
                Flow::End => break,
                Flow::Jump(label) => {
                    pc = *program
                        .labels
                        .get(&label)
                        .ok_or_else(|| format!("Unknown jump label {label}"))?
                }
                _ => pc += 1,
            }
        }
        self.notes.push("Raw f64; output writes are events, not aggregated project totals. Adaptive rounding, cleanup and project DB side effects are not emulated.".into());
        Ok(RunResult {
            method: self.method,
            steps,
            variables: self.variables,
            writes: self.writes,
            trace,
            notes: self.notes,
        })
    }
    fn cell(
        &self,
        method: &str,
        table: &str,
        dict: bool,
        row: &crate::data::TableRow,
        col: usize,
    ) -> Result<Value> {
        if col == 21 {
            return Ok(Value::Text(row.mark.clone()));
        }
        let raw = row
            .cells
            .get(col.checked_sub(1).ok_or("Column must be >=1")?)
            .ok_or("Column out of range")?;
        if dict {
            return Ok(Value::Text(raw.clone()));
        }
        let meta = self
            .db
            .columns
            .get(&(method.into(), table.into(), col))
            .ok_or_else(|| format!("Missing column metadata for {table}:{col}"))?;
        if meta.kind == "Ч" {
            return Ok(Value::Number(if raw.trim().is_empty() {
                0.
            } else {
                raw.trim()
                    .parse()
                    .map_err(|_| format!("Non-numeric coefficient {raw:?}"))?
            }));
        }
        if meta.kind == "Д" {
            return Err("Range-valued table cells are not implemented".into());
        }
        Ok(Value::Text(raw.clone()))
    }
    fn tab(&mut self, raw: &str) -> Result<Value> {
        let args = expr::split_top(raw, ',')?;
        if args.len() != 3 {
            return Err("TAB requires three arguments".into());
        }
        let mut spec = args[0].trim().to_lowercase();
        let mut method = self.method.clone();
        if spec.starts_with('(') {
            let end = spec.find(')').ok_or("Invalid cross-method TAB")?;
            method = spec[1..end].to_string();
            spec = spec[end + 1..].trim().into();
        }
        let dict = spec.ends_with("(s)");
        if dict {
            spec.truncate(spec.len() - 3);
        }
        let id = if let Some(expression) = spec.strip_prefix('=') {
            table_id(&self.eval(&expr::parse(expression)?)?.text())
        } else {
            table_id(&spec)
        };
        let col_value = self.eval(&expr::parse(&args[2])?)?;
        let col = match col_value {
            Value::Number(n) => nonnegative_index(n)?,
            Value::Text(ref name) => self
                .db
                .columns
                .iter()
                .find(|((m, t, _), c)| m == &method && t == &id && c.name == name.to_lowercase())
                .map(|((_, _, c), _)| *c)
                .ok_or("Unknown named column")?,
            _ => return Err("Invalid TAB column".into()),
        };
        let key = (method.clone(), id.clone(), dict);
        let rows = self
            .db
            .tables
            .get(&key)
            .ok_or_else(|| format!("Missing table {method}:{id} dictionary={dict}"))?;
        let selector = args[1].trim();
        let (start_expr, filter) = tab_filter(selector)?;
        let mut not_found_error = 4014.;
        let chosen = if let Some(filter) = filter {
            let start_expr = expr::parse(start_expr.unwrap_or("0"))?;
            let physical = dict && references(&start_expr, "_row_");
            let start = self.eval(&start_expr)?.number()?;
            if start < 0. {
                return Err("TAB multi-selection is not implemented".into());
            }
            let start = nonnegative_index(start)?;
            let expression = if filter.starts_with(['=', '<', '>', '#', '!', '$']) {
                let lhs = if col == 21 {
                    "[21]".into()
                } else if dict {
                    "[1]".into()
                } else {
                    let codes: Vec<_> = self
                        .db
                        .columns
                        .iter()
                        .filter(|((m, t, _), c)| {
                            m == &method && t == &id && !c.dictionary.is_empty()
                        })
                        .map(|((_, _, c), _)| format!("[{c}]"))
                        .collect();
                    if codes.is_empty() {
                        format!("[{col}]")
                    } else {
                        codes.join("+")
                    }
                };
                expr::parse(&format!("({lhs}){filter}"))?
            } else {
                expr::parse(filter)?
            };
            let mut candidates = Vec::new();
            for row in rows.iter().filter(|r| {
                if physical {
                    r.record >= start
                } else {
                    r.number >= start
                }
            }) {
                let context = (1..=21)
                    .map(|c| {
                        if c == 21
                            || (c <= row.cells.len()
                                && (dict
                                    || self.db.columns.contains_key(&(
                                        method.clone(),
                                        id.clone(),
                                        c,
                                    ))))
                        {
                            self.cell(&method, &id, dict, row, c)
                        } else {
                            Ok(Value::Text(
                                row.cells.get(c - 1).cloned().unwrap_or_default(),
                            ))
                        }
                    })
                    .collect::<Result<_>>()?;
                let previous = self.table_context.replace(context);
                let result = self.eval(&expression);
                self.table_context = previous;
                if result?.boolean()? {
                    candidates.push(row.number);
                    if start > 0 {
                        break;
                    }
                }
            }
            if start > 0 {
                candidates.first().copied()
            } else if candidates.is_empty() {
                None
            } else {
                self.select_row(&method, &id, &candidates)?
            }
        } else {
            let expression = expr::parse(selector)?;
            let physical = dict && references(&expression, "_row_");
            let n = self.eval(&expression)?.number()?;
            if n == 0. {
                self.select_row(
                    &method,
                    &id,
                    &rows.iter().map(|r| r.number).collect::<Vec<_>>(),
                )?
            } else if n > 0. {
                not_found_error = 4018.;
                let n = positive_index(n)? + 1;
                if physical {
                    rows.iter().find(|r| r.record == n).map(|r| r.number)
                } else {
                    Some(n)
                }
            } else {
                return Err("TAB multi-selection is not implemented".into());
            }
        };
        let Some(row) = chosen.and_then(|n| rows.iter().find(|r| r.number == n)) else {
            self.variables.insert("_nvib_".into(), Value::Number(0.));
            self.variables
                .insert("_err_".into(), Value::Number(not_found_error));
            return Ok(Value::Text(String::new()));
        };
        let value = self.cell(&method, &id, dict, row, col)?;
        self.variables.insert(
            "_row_".into(),
            Value::Number(if dict { row.record } else { row.number } as f64),
        );
        self.variables
            .insert("_col_".into(), Value::Number(col as f64));
        self.variables.insert("_nvib_".into(), Value::Number(1.));
        self.variables.insert("_err_".into(), Value::Number(0.));
        self.variables
            .insert("_kod_".into(), Value::Text(String::new()));
        self.variables
            .insert("_name_".into(), Value::Text(String::new()));
        if dict {
            self.variables
                .insert("_kod_".into(), Value::Text(row.cells[0].clone()));
            self.variables
                .insert("_name_".into(), Value::Text(row.cells[1].clone()));
        } else if let Some(meta) = self.db.columns.get(&(method.clone(), id.clone(), col)) {
            if !meta.dictionary.is_empty() {
                self.variables
                    .insert("_kod_".into(), Value::Text(value.text()));
                if let Some(vocab) = self.db.tables.get(&(method, meta.dictionary.clone(), true)) {
                    let name = vocab
                        .iter()
                        .find(|r| r.cells[0] == value.text())
                        .map(|r| r.cells[1].clone())
                        .ok_or("Missing dictionary entry")?;
                    self.variables.insert("_name_".into(), Value::Text(name));
                } else if meta.dictionary != "зв" {
                    return Err(format!("Missing dictionary {}", meta.dictionary));
                }
            }
        }
        Ok(value)
    }
    fn select_row(
        &mut self,
        method: &str,
        id: &str,
        candidates: &[usize],
    ) -> Result<Option<usize>> {
        let cursor = self.selection_cursors.entry(self.line).or_default();
        let queue = self.scenario.selections.get(&self.line).ok_or_else(|| {
            format!(
                "TAB selection required for line {} ({method}:{id})",
                self.line
            )
        })?;
        let selected = *queue.get(*cursor).ok_or("TAB selection queue exhausted")?;
        if !candidates.contains(&selected) {
            return Err(format!(
                "TAB selected row {selected} is outside the matching rows"
            ));
        }
        *cursor += 1;
        Ok(Some(selected))
    }
}
// Recognize only the documented optional (start) prefix, not a parenthesized
// numeric row expression. Quotes and nested arithmetic are balanced by split_top.
fn tab_filter(selector: &str) -> Result<(Option<&str>, Option<&str>)> {
    let is_filter = |s: &str| s.starts_with(['[', '=', '<', '>', '#', '!', '$']);
    if selector.starts_with('(') {
        for (i, c) in selector.char_indices().skip(1) {
            if c == ')' && expr::split_top(&selector[1..i], ',').is_ok() {
                let rest = selector[i + 1..].trim();
                if is_filter(rest) {
                    return Ok((Some(&selector[1..i]), Some(rest)));
                }
                break;
            }
        }
    }
    if is_filter(selector) {
        Ok((None, Some(selector)))
    } else {
        Ok((None, None))
    }
}
fn references(e: &Expr, variable: &str) -> bool {
    match e {
        Expr::Var(name) => name == variable,
        Expr::Unary(_, a) => references(a, variable),
        Expr::Binary(_, a, b) => references(a, variable) || references(b, variable),
        Expr::Call(_, args) => args.iter().any(|e| references(e, variable)),
        _ => false,
    }
}
fn nonnegative_index(n: f64) -> Result<usize> {
    if !n.is_finite() || n < 0. || n.fract() != 0. || n > 1_000_000. {
        Err(format!("Invalid integer index {n}"))
    } else {
        Ok(n as usize)
    }
}
fn positive_index(n: f64) -> Result<usize> {
    nonnegative_index(n)?
        .checked_sub(1)
        .ok_or("Index is one-based".into())
}
fn indices(v: &[Value]) -> Result<(usize, usize)> {
    if v.len() != 2 {
        return Err("Two array indices required".into());
    }
    Ok((
        positive_index(v[0].number()?)?,
        positive_index(v[1].number()?)?,
    ))
}
fn array_offset(v: &[Value], nr: usize, nc: usize) -> Result<usize> {
    let offset = if v.len() == 1 {
        positive_index(v[0].number()?)?
    } else {
        let (r, c) = indices(v)?;
        if r >= nr || c >= nc {
            return Err("Array index out of bounds".into());
        }
        r * nc + c
    };
    if offset >= nr * nc {
        return Err("Array index out of bounds".into());
    }
    Ok(offset)
}
