# rulesfinder

Machine-learn password mangling rules!

This tool finds efficient password mangling rules (for John the Ripper or Hashcat) for a given dictionnary and a list of passwords.

The tool is currently alpha quality.

## tl;dr

You need the rust toolchain to build this tool.

```
cargo build --release
target/release/johnrules -w path/to/wordlist --cleartexts path/to/cleartexts -n 50 -t 7 --minsize 3 | tee result
```

Here, `50` is the cutoff value, meaning that a rule has to crack at least 50 passwords to be kept, and 7 is the number of threads.

Beware, this program can use a lot of memory very quickly!
