use era_engine::{
    data::Database,
    engine::{Program, Runtime, Scenario},
    expr::{self, Value},
    Result,
};
use serde_json::json;
use std::{collections::BTreeMap, env, fs, hint::black_box, path::PathBuf, time::Instant};

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    const USAGE: &str = "Usage: era-engine demo | run scenario.json | run-batch cases.json [workers] | audit | bench [iterations]\nData commands require ERA_DATA=/path/to/recovered. demo needs no ERA files.";
    match args.first().map(String::as_str) {
        None | Some("--help" | "-h") => {
            println!("{USAGE}");
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("era-engine {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("demo") if args.len() == 1 => {
            println!(
                "{}",
                serde_json::to_string_pretty(&era_engine::demo::run()?)
                    .map_err(|e| e.to_string())?
            );
            return Ok(());
        }
        Some("run") if args.len() == 2 => {}
        Some("run-batch") if (2..=3).contains(&args.len()) => {}
        Some("audit") if args.len() == 1 => {}
        Some("bench") if (1..=2).contains(&args.len()) => {}
        _ => return Err(USAGE.into()),
    }
    let default =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../reverse_engineering/recovered");
    let root = env::var_os("ERA_DATA")
        .map(PathBuf::from)
        .unwrap_or(default);
    let db = Database::load(&root).map_err(|e| format!("{e}\nSet ERA_DATA to your local recovered JSON directory; try 'era-engine demo' without vendor data."))?;
    let output=match args.first().map(String::as_str){
        Some("run-batch")=>{
            let file=args.get(1).ok_or("run-batch requires an array of scenarios in JSON")?;
            let workers=args.get(2).map(|s|s.parse::<usize>().map_err(|_|"Invalid worker count")).transpose()?.unwrap_or(1);
            let scenarios:Vec<Scenario>=serde_json::from_slice(&fs::read(file).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
            serde_json::to_value(era_engine::run_batch(&db,&scenarios,workers)?).map_err(|e|e.to_string())?
        },
        Some("run")=>{
            let file=args.get(1).ok_or("run requires scenario.json")?;
            let scenario:Scenario=serde_json::from_slice(&fs::read(file).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
            let rows=db.methods.get(&scenario.method).ok_or("Unknown method")?;
            let program=Program::compile(&scenario.method,rows)?;
            serde_json::to_value(Runtime::new(&db,scenario).run(&program)?).map_err(|e|e.to_string())?
        },
        Some("audit")=>{
            let mut methods=Vec::new();let mut parsed=0;let mut total=0;
            for (code,rows) in &db.methods{
                let mut errors=Vec::new();
                for row in rows{total+=1;match expr::statement(&row.formula){Ok(_)=>parsed+=1,Err(error)=>errors.push(json!({"line":row.line,"record":row.record,"formula":row.formula,"error":error}))}}
                let external:Vec<_>=rows.iter().filter(|r|r.formula.to_lowercase().contains("indll(")).map(|r|json!({"line":r.line,"formula":r.formula})).collect();
                let compilation=Program::compile(code,rows).err();
                methods.push(json!({"method":code,"rows":rows.len(),"syntax_errors":errors,"external_calls":external,"compilation_error":compilation}));
            }
            json!({"rows":total,"syntax_parsed":parsed,"warning":"Syntax parsing is not execution coverage. TAB variants, functions and host callbacks may fail at runtime.","methods":methods})
        },
        Some("bench")=>{
            let count:usize=args.get(1).map(|v|v.parse().map_err(|_|"Invalid iteration count")).transpose()?.unwrap_or(100_000);
            if count==0{return Err("Iteration count must be positive".into());}
            let expressions:Vec<_>=[28,29].iter().map(|n|{
                let row=db.methods.get("0092").and_then(|rows|rows.iter().find(|r|r.line==*n)).ok_or_else(||format!("Benchmark requires method 0092 line {n}"))?;Ok((row.variable.to_lowercase(),expr::parse(&row.formula)?))
            }).collect::<Result<_>>()?;
            let scenario=Scenario{method:"0092".into(),initial:BTreeMap::from([
                ("gi".into(),Value::Number(0.433)),("f".into(),Value::Number(2.)),("t".into(),Value::Number(8.)),("n".into(),Value::Number(250.))]),..Scenario::default()};
            let mut rt=Runtime::new(&db,scenario);let mut sum=0.;
            let start=Instant::now();
            for i in 0..count{rt.variables.insert("f".into(),Value::Number(black_box(1.+(i%97) as f64/97.)));
                for(name,e)in &expressions{let v=rt.eval(e)?;rt.variables.insert(name.clone(),v);}
                sum+=rt.variables["gmi"].number()?+rt.variables["mmi"].number()?;
            }
            let ast_seconds=start.elapsed().as_secs_f64();black_box(sum);
            let start=Instant::now();let mut native_sum=0.;
            for i in 0..count{let f=black_box(1.+(i%97) as f64/97.);let gi=black_box(0.433f64);let t=black_box(8f64);let n=black_box(250f64);
                let g=gi*f;let m=gi*f*t*n*3600.*10f64.powf(-6.);native_sum+=g+m;}
            let native_seconds=start.elapsed().as_secs_f64();black_box(native_sum);
            json!({"iterations":count,"rust_ast_seconds":ast_seconds,"rust_native_seconds":native_seconds,"checksum":sum,"native_checksum":native_sum,
                "scope":"Warm kernel only: recovered 0092 lines 28/29. JSON loading, compilation and I/O excluded; not a benchmark against ERA.exe."})
        },
        _=>return Err("Usage: era-engine run scenario.json | run-batch cases.json [workers] | audit | bench [iterations]; optional ERA_DATA=/path/to/recovered".into())
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|e| e.to_string())?
    );
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
