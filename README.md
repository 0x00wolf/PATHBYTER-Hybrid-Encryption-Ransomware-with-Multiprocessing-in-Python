<p align="center">
<!-- Place this tag where you want the button to render. -->
<a class="github-button" href="https://github.com/0x00wolf/PATHBYTER-Hybrid-Encryption-Ransomware-with-Multiprocessing-in-Python" data-icon="octicon-star" aria-label="Star 0x00wolf/PATHBYTER-Hybrid-Encryption-Ransomware-with-Multiprocessing-in-Python on GitHub">Like this project? Give it a star! Click here</a>

# Pathbyter: Hybrid Encryption Ransomware with Multiprocessing in Python
***
Pathbyter is a lightning-fast and fully functioning proof-of-concept ransomware that emulates the advanced tactics employed in the development of malware like Conti, REvil, WannaCy, Lockbit, and Ryuk. 


## Table of Contents

1. [Why build Pathbyter?](#why-build-pathbyter)
2. [Disclaimer](#Disclaimer)
3. [Requirements](#Requirements)
4. [How fast is Pathbyter?](#how-fast-is-pathbyter)
5. [What's in this repository?](#whats-in-this-repository)
7. [How Pathbyter works:](#how-pathbyter-works)


## Why build Pathbyter?

I am a very curious person. While reading security research reports on different ransomware strains, I saw a pattern of programmatic features common among them that interested me. I researched Python ransomware projects on Github to see what solutions others had come up with to emulate those features. Almost every example I read encrypted files in an os.walk() loop and then displayed a ransom message asking for Bitcoin. Many lacked most if not all of the elements that I was really curious about. I had some ideas as to how I would go about implementing those features. Mix in some time and creative problem solving and we arrive at Pathbyter.

## Disclaimer

Pathbyter is intended for educational purposes or for approved red team exercises only. The author does not take any responsibility for the misuse of this software, nor does he approve of the redistribution of this software for anything other than legitimate educational and/or professional reasons. **Do not use Pathbyter on a box you have not been given express permission to run it on.** There isn't a ransom message built into this project for a reason. 

Do give me a star if you like the code!


## Requirements

Pathbyter uses one non-Standard Python Library module, pycryptodome, to gain access to the various cryptographic ciphers that it provides. 

To install pycryptodome use:

```pip install pycryptodome```

Check out the [readthedocs](https://pycryptodome.readthedocs.io/en/latest/).

## How fast is Pathbyter?

Pathbyter, as it says in the intro blurb, is wicked fast. To generate test data that would allow me to compare Pathbyter's encryption performance to 'real' ransomware in the wild, [I used research courtesy of Splunk.](https://www.splunk.com/en_us/blog/security/gone-in-52-seconds-and-42-minutes-a-comparative-analysis-of-ransomware-encryption-speed.html) 

**Splunk**:
>We tested every sample across all four host profiles, which amounted to 400 different ransomware runs (10 families x 10 samples per family x 4 profiles). In order to measure the encryption speed, we gathered 98,561 test files (pdf, doc, xls, etc.) from a public file corpus, totaling 53GB.

**The researchers at Splunk arrived at the following results:**

![ALT text](imgs/splunktests.png)

To use this dataset as a meaningful comparison for Pathbyter I took the following steps: 
1) I wrote a Python script that generated 100,000 garbage files, each 512kb, full of a quote from the movie Hackers on repeat (sorry, not sorry). The files being different 'types' is redundant if they are the same size. Splunk used a file corpus which is just a collection of different text documents. File types are identified by the OS via the magic bytes that are at the beginning of every file. We are flipping bits and not interested in the content so a corny movie quote repeated billions of times is more than sufficient.
2) I streamlined Pathbyter's code (dropped internal function calls for the main attack loop), to try and improve optimization at runtime for a reduction in the cleanliness of the code.
3) I let 'er rip, bud.

**An example of Pathbyter's results on a Windows 10 pc with a Ryzen 5800x CPU and 32Gb DDR4 ram:**

![ALT text](imgs/pbresults.png)

**Pathbyter's elapsed time to encrypt 100,000 512kb files over 10 runs:**

| Run | Elapsed Time  |
| --- | ------------  |
|  1  | input me      |
|  2  | input me      |
|  3  | input me      |
|  4  | input me      |
|  5  | input me      |
|  6  | input me      |
|  7  | input me      |
|  8  | input me      |
|  9  | input me      |
| 10  | input me      |

Pathbyter's median encryption time was ''. 


With multiprocessing you can speed up Python programs by a significant multiplier, particularly for CPU heavy tasks like encryption.   

## What's in this repository?

![ALT text](imgs/repotree.png)

- **pathbyterPoC.py** is the proof-of-concept version of Pathbyter, which will generate a series of dummy files and then encrypt and decypt them. It generates a JSON log file, show useful information to the terminal, and is safe to run. Usage: `python3 pathbyterPoC.py`. The code is intentionally meant to be readable, and broken into logical functions to help the reader understand what's happening. When I first made Pathbyter I used a JSONL key-value database to save the encrypted file paths, RSA wrapped AES keys, and their associated nonces. However, after I got everything to work I reworked the code to append the keys and nonces to the encrypted files, which is a common programmatic element in all of the advanced ransomware attacks in the wild. I have included the original exec_ransomware() and ctrl_z_ransomware() functions that use the JSONL kvdb format commented out for reference.
- The **red-teaming** directory includes the streamlined version of Pathbyter with some minimal argv tooling.
- The **speed-test** directory contains the ingredients I used to conduct the aforementioned speed tests. This version of Pathbyter has the same main code as the red-teaming version, but without argv tooling, and with added information printed out after each run.
- The **utils** directory contains test scripts I used to build Pathbyter like getting the size in bytes of a string, and a convenient/portable System class. The System class checks for an internet connection, fetchs a public ip if there is internet, and on instantiation collects a sequence of useful information about the box it was created upon. It also has a built in path_crawl() method that can be used to fetch a list of files recursively from a selected parent directory or using os.path.expanduser('~') on Mac, Windows, or Linux. I plan on expanding the system path in the future to be able to collect information about devices on the local network and other fun features - stay tuned. 

## How Pathbyter works:

The implementations used in Pathbyter differ from the examples on pycryptodome's read the docs due to the fact that keys are only written to disk after being encrypted. The reason for this is that malicious actors would want to avoid writing to disk is to prevent a skilled defender from recovering the RSA private key even if it was deleted, and thwarting the attack. Pathbyter uses a combination of ciphers, both AES CTR and CBC, as well as RSA. It uses a 4096 bit hardcoded RSA public key (the attacker's key), a 2048-RSA session key pair, and a new AES key for every file that it encrypts.



are as follows: First, Pathbyter uses the included System class path_crawl() method to return a list of all the target files before encryption begins, which streamlines the main attack function, exec_attack(). To override Python's global-interpreter-lock, Pathbyter uses a multiprocessing pool, which will create a number of child processes equaL to the number of CPU cores in the victim system. Pathbyter invokes the multiprocessing poool map function, which takes two arguments: a function and an iterator
</p>
<!-- Place this tag in your head or just before your close body tag. -->
<script async defer src="https://buttons.github.io/buttons.js"></script>
