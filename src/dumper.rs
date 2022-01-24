use crate::rules::genmutate;
use structopt::StructOpt;

mod rules;

lazy_static::lazy_static! {
    static ref CONVS: rules::Converts = rules::make_converts();
}

#[derive(Debug)]
enum Mode {
  DumpRules,
  ApplyRules,
}

impl std::str::FromStr for Mode {
  type Err = &'static str;
  fn from_str(s: &str) -> Result<Self, Self::Err> {
    match s {
      "dump" => Ok(Mode::DumpRules),
      "apply" => Ok(Mode::ApplyRules),
      _ => Err("Accepted modes are dump and apply"),
    }
  }
}

#[derive(Debug, StructOpt)]
struct Opts {
  /// Execution mode
  #[structopt(long = "mode", default_value("dump"))]
  mode: Mode,
  /// Only use rules that work in Hashcat
  #[structopt(long = "hashcat")]
  hashcat: bool,
}

fn main() {
  let opt = Opts::from_args();
  match opt.mode {
    Mode::DumpRules => {
      for r in genmutate().into_iter().filter(|rs| {
        if opt.hashcat {
          rs.iter().all(rules::hashcat_rule)
        } else {
          rs.iter().all(rules::john_rule)
        }
      }) {
        println!("{} // {:?}", rules::show_rules(&r, opt.hashcat), &r);
      }
    }
    Mode::ApplyRules => {
      panic!("TODO");
    }
  }
}
