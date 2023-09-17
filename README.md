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

**To use this dataset as a meaningful comparison for Pathbyter I took the following steps:**

1) I wrote a Python script that generated 100,000 garbage files, each 512kb, full of a quote from the movie Hackers on repeat (sorry, not sorry). The files being different 'types' is redundant if they are the same size. Splunk used a file corpus which is just a collection of different text documents. File types are identified by the OS via the magic bytes that are at the beginning of every file. We are flipping bits and not interested in the content so a corny movie quote repeated billions of times is more than sufficient.
2) I streamlined Pathbyter's code (dropped internal function calls for the main attack loop), to try and improve optimization at runtime for a reduction in the cleanliness of the code.
3) I let 'er rip, bud.

**An example of Pathbyter's results on a Windows 10 pc with a Ryzen 5800x CPU and 32Gb ram:**

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

**Pathbyter's median encryption time was ''** 

**Speed 2: Cruise Control (Observerations):**
Encryption is a CPU heavy task. If you have one process encrypting all the files, it is obviously slower than spawning as many new processes are there are logical processors present, splitting the target files up equally between them, and having each process encrypt their share of the files asynchronously. Basically, with multiprocessing you can speed up encrypting files, even if the code is written in a scripted language like Python, and it can be by a significant multiplier. 

Appending the encrypted keys to the files means that you can significantly limit the number of read and write operations that the processes have to perform over a large number of files. You read the file into a variable in write bytes mode and then close it > generate a new AES-128 bit key > encrypts the variable with the new key and an AES CTR cipher > wraps the AES key with the session RSA public key > reopens the file in write bytes mode > write the encrypted data and the key. So for each file you only read and write to the disk once. Pathbyter uses the fastest AES cipher, CTR or Counter mode to encrypt files, but AES CBC to encrypt the RSA session private key (just to spice things up a bit).

Pathbyter only uses in-memory encryption. This means that decryption keys, the session RSA private key or any of the AES keys, are never written to disk before being encrypted. This is something malicious actors do to prevent the recovery of the keys by a skilled defender working on behalf of the ransomware victim. Deleted items may still be stored on the same sector of the disk if that portion of the harddrive hadn't been written oversince. To capture a key in-memory, a snapshot of the ram would need to have been taken at the moment of encryption. This method also further limits input and output operations that en-masse can bog down the processors and lengthen the overall runtime.

## What's in this repository?

![ALT text](imgs/repotree.png)

- **pathbyterPoC.py** is the proof-of-concept version of Pathbyter, which will generate a series of dummy files and then encrypt and decypt them. It generates a JSON log file, show useful information to the terminal, and is safe to run. Usage: `python3 pathbyterPoC.py`. The code is intentionally meant to be readable, and broken into logical functions to help the reader understand what's happening. When I first made Pathbyter I used a JSONL key-value database to save the encrypted file paths, RSA wrapped AES keys, and their associated nonces. However, after I got everything to work I reworked the code to append the keys and nonces to the encrypted files, which is a common programmatic element in all of the advanced ransomware attacks in the wild. I have included the original exec_ransomware() and ctrl_z_ransomware() functions that use the JSONL kvdb format commented out for reference.
- **private.pem** is the associated private key to the hardcoded public key used in every iteration of Pathbyter in this repo.
- The **red-teaming** directory includes the streamlined version of Pathbyter with some minimal argv tooling.
- The **speed-test** directory contains the ingredients I used to conduct the aforementioned speed tests. This version of Pathbyter has the same main code as the red-teaming version, but without argv tooling, and with added information printed out after each run.
- The **utils** directory contains test scripts I used to build Pathbyter like getting the size in bytes of a string, and a convenient/portable System class. The System class checks for an internet connection, fetchs a public ip if there is internet, and on instantiation collects a sequence of useful information about the box it was created upon. It also has a built in path_crawl() method that can be used to fetch a list of files recursively from a selected parent directory or using os.path.expanduser('~') on Mac, Windows, or Linux. I plan on expanding the system path in the future to be able to collect information about devices on the local network and other fun features - stay tuned.


## How Pathbyter works:

**The ransomware attack:**

- At runtime Pathbyter generates an instance of the System class, checking for a public ip, and gathering information about the victim box. It then uses a System class method to generate a target id card, which includes a UUID as well as network, user and hardware information.
- Pathbyter generates a new AES 128-bit key and uses it to encrypt the id card with an AES CBC cipher.
- Using the attacker's hardcoded  RSA-4096 public key, Pathbyter encrypts the AES key.
- Then the encrypted id card, associated encrypted AES key and the key's initialization vector are written to a JSON database, 'donotdelete.json'.
- Next, a new session RSA keypair is generated.
- A note: A session keypair is generated at the start of each attack, so that the victim is able to share the encrypted session RSA private key with the attackers, and they can return the unencrypted private key, without compromising the confidentiality of the attacker's private key associated with the hardcoded public key used in every attack.
- The session RSA private key is immediately encrypted with a new AES key in memory and function scope, the new AES key is wrapped with the attacker's public key, and the necessary information is added to the JSON decryption stub.
- The session RSA public key is returned to the main program ready to encrypt.
- Pathbyter uses the System.path_crawl() method to generate a list of a target files.
- Pathbyter generates a multiprocessing Pool class instance, which takes one argument - the number of processors to generate new processes with.
- Pathbyter uses the Pool class' map method, which takes two arguments, a function and an iterable. The map method splits up the iterable equally among the processes in the pool, and then runs the function asynchronously on the different processes, each passing their set of variables one at a time to the function in a loop until all are finished.
- The attack function: opens the target file in read bytes mode, reads the file's bytes into a variable > generates a new AES-128 bit key > uses an AES CTR cipher to encrypt the file data > wraps the AES key with the session RSA public key > reopens the file in write bytes mode > writes the encrypted data and concatenates the wrapped AES key and nonce to the end of the file.
- After the encryption process is finished, Pathbyter appends '.crypt' to all of the filenames in the target files list.
- Finally Pathbyter will print out the encryption time instead of present a ransom note.
  
**Decryption:**

- The decryption process is completely unconcerned with speed. It uses a System.path_crawl() to collect all the files that end in .crypt and decrypts them one at a time. It slices the last 314 bytes off of each file when it opens them in read bytes mode to recover the encrypted AES key and nonce. It writes the unencrypted RSA public key out, which is kind of unthematic in that an attacker would do this remotely, but it was convenient to just have the private key sitting in the same folder.
