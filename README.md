# rulesfinder

Machine-learn password mangling rules!

This tool finds efficient password mangling rules (for John the Ripper or Hashcat) for a given dictionnary and a list of passwords.

The tool is currently alpha quality.

## tl;dr

You need the rust toolchain to build this tool.

```
cargo build --release
ulimit -m 8192  # limit memory usage to 8G
target/release/johnrules -w path/to/wordlist --cleartexts path/to/cleartexts -n 50 -t 7 --minsize 3 | tee result
```

Here, `50` is the cutoff value, meaning that a rule has to crack at least 50 passwords to be kept, and 7 is the number of threads.

Beware, this program can use a lot of memory very quickly!

## What is it?

A long form article will soon be published.

## Performance

All measurements have been conducted on my laptop while I am doing something else with it.
*These measurements are just here to illustrate what you should expect with regards to resource usage.*

All measurements have been conducted using a cleartext database of 1642068 passwords, and a parallelism level of 7.

| Dictionary size | Minimum substring size | Cutoff | Memory usage | Run time | Rules found | Estimated passwords cracked |
|:---------------:|------------------------|--------|--------------|----------|-------------|-----------------------------|
| 3559            | 5                      | 20     | 5.5GB        | 63s      | 1520        | 106610                      |
| 3559            | 4                      | 20     | 7.6GB        | 156s     | 2002        | 131752                      |
| 3559            | 5                      | 100    | 5.5GB        | 32s      | 257         | 58207                       |
| 3559            | 3                      | 100    | 14.7GB       | 128s     | 303         | 70026                       |
| 12645           | 5                      | 100    | 5.9GB        | 56s      | 486         | 143838                      |
| 102774 `[1]` | 5                      | 100    | 6GB          | 89s      | 464         | 135873                      |
| 303872          | 5                      | 100    | 7.5GB        | 346s     | 889         | 361561                      |

`[1]`: this is an outlier, because I used a generic spellchecking dictionnary instead of a dictionnary specilized for password cracking.

The processing is two parts:

 * the first part, that is the most memory intensive, is exclusively influenced by the size of the cleartext corpus ;
 * the second part is, all other parameters being the same, roughly proportional in time spent and memory used to the size of the dictionnary.

The above *estimated passwords cracked* column is the amount of passwords in the cleartext corpus that would have been cracked with the generated rules using the given dictionnary.
As with all things machine learning it does not directly reflect the ruleset performance.
Increasing this value mindlessly will be counter productive, as it will lead to:

 * more rules, reducing the overall efficiency of the ruleset ;
 * overfit.

As a rule of thumb, I recommend:

 * having a a minimum substring size of 4 or 5 ;
 * only using real passwords in the cleartext corpus ;
 * using dictionnaries you will actually use during a cracking session. That means short dictionnaries for rules meant for hard hashes, and long dictionnaries for rules meant for fast hashes.

