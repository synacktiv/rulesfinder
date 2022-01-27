# rulesfinder

Machine-learn password mangling rules!

This tool finds efficient password mangling rules (for John the Ripper or Hashcat) for a given dictionary and a list of passwords.

The tool is currently alpha quality.

## tl;dr

You need the rust toolchain to build this tool. You can either directly install:

```
cargo install --git https://github.com/synacktiv/rulesfinder
ulimit -d 8388608  # limit memory usage to 8GBB
rulesfinder -w path/to/wordlist --cleartexts path/to/cleartexts -n 50 -t 7 --minsize 3 | tee result
```

Or, after cloning this repository:
```
ulimit -d 8388608  # limit memory usage to 8GBB
cargo run --release --  -w path/to/wordlist --cleartexts path/to/cleartexts -n 50 -t 7 --minsize 3 | tee result
```

Here, `50` is the cutoff value, meaning that a rule has to crack at least 50 passwords to be kept, and 7 is the number of threads.

Beware, this program can use a lot of memory very quickly!

## What is it?

A long form article can be [read here](https://www.synacktiv.com/posts/tool/rulesfinder-automatically-create-good-password-cracking-rulesets.html). It explains what the idea behind the tool is, and what it does.

## Performance

All measurements have been conducted on my laptop while I am doing something else with it.
*These measurements are just here to illustrate what you should expect with regards to resource usage.*

Memory usage for the first phase

| Cleartext size | Cleartext words | minsize=3 | minsize=4 | minsize=5 | minsize=6 |
|:--------------:|-----------------|-----------|-----------|-----------|-----------|
| 11.264 MB      | 1M words        | 3767MB    | 3245MB    | 2732MB    | 2255MB    |
| 16.9 MB        | 1.5M words      | 7365MB    | 6262MB    | 5273MB    | 4742MB    |
| 22.528 MB      | 2M words        | 9263MB    | 5273MB    | 6518MB    | 5389MB    |
| 42.848 MB      | 3.8M words      | 14347MB   | 4742MB    | 10529MB   | 8885MB    |

The processing is two parts:

 * the first part, that is the most memory intensive, is exclusively influenced by the size of the cleartext corpus and minimum substring size ;
 * the second part is influenced by all parameters, but, all other parameters being the same, roughly proportional in time spent and memory used to the size of the dictionary.

The above *estimated passwords cracked* column is the amount of passwords in the cleartext corpus that would have been cracked with the generated rules using the given dictionary.
As with all things machine learning it does not directly reflect the ruleset performance.
Increasing this value mindlessly will be counter productive, as it will lead to:

 * more rules, reducing the overall efficiency of the ruleset ;
 * overfit.

As a rule of thumb, I recommend:

 * having a a minimum substring size of 4 or 5, note that memory usage for the first phase is mostly linear with the size of the plaintext corpus ;
 * only using real passwords in the cleartext corpus ;
 * using dictionaries you will actually use during a cracking session. That means short dictionaries for rules you will use against hard hashes, and long dictionaries for rules you will use against fast hashes.

