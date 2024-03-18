# CTF Tools
This repository is a place where I want to keep all the useful *resources/websites/tools* to solve CTF challenges. All the tools will be divided by category, in order to have a better organization.

This repo is for me but also for my CTF team, and why not for whoever will get to this page.

It will contain even some "obvious" links, like the ASCII table and so on, because it is a page indended to be kept open during CTFs: you never know what will come in handy!

## Training 🚩
> A list of useful websites to train our skills and knowledge.
- [picoCTF](https://picoctf.org/)
- [capturetheflag](https://capturetheflag.it/risorse/come-imparo)
- [overthewire](https://overthewire.org/wargames/)
- [pwnable](http://pwnable.kr/)

## General 📋
#### Tools
- [John Hammond - Katana](https://github.com/JohnHammond/ctf-katana): **huge repo of very useful CTF tools**, thank you John, my repo now looks useless 
- [Cyberchef](https://gchq.github.io/CyberChef/): huge tool to perform **every type of calculation of any category**
- [Hex Editor](https://hexed.it/): online **hex editor** for files
- [Online Converter](https://www.rapidtables.com/convert/number/ascii-hex-bin-dec-converter.html): **ASCII/Hex/Dec/Bin/b64 converter** tool online
- [XOR Calculator](http://xor.pw/)
- [Resource Saver](https://chrome.google.com/webstore/detail/save-all-resources/abpdnfjocnmdomablahdcfnoggeeiedb?hl=en-US): Chrome extension to **download all the res of a website**
- [Github Secrets](https://github.com/neodyme-labs/github-secrets): search for **dangling or force-pushed commits** in a Github repo
- [Zip Password Cracker](https://passwordrecovery.io/zip-file-password-removal/): a realy useful and free **online zip password finder**
- [Regex Check](https://www.debuggex.com/): check **regular expressions** online
#### Resources
- [ASCII Table](http://www.asciitable.com/)

## Cryptography 🔒
#### Tools
- [dCode](https://www.dcode.fr): **crypto heaven**
- [QuipQuip](https://quipqiup.com/): online **substitution cipher solver** with frequency analysis, also allows to insert frequency hints
- [Big Numbers Calculator 1](http://www.javascripter.net/math/calculators/100digitbigintcalculator.htm): an online **calculator for huge integers**
- [Big Numbers Calculator 2](https://defuse.ca/big-number-calculator.htm): an online **calculator for huge integers**, worse UI but maybe better performance
- [RSA Calculator](https://www.cryptool.org/en/cto/highlights/rsa-step-by-step): online **RSA parameters calculator with encryption/decryption**, works also with big numbers 
- [Inverse mod N Calculator](https://www.dcode.fr/modular-inverse): compute the **modular inverse of a number**, even with big numbers
- [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool): Python tool to perform **RSA attacks**
- [FactorDB](http://factordb.com/): find **well-known integer factorization**
- [CrackStation](https://crackstation.net/): online **hash cracker** (md5, sha, ...)
- [Vigenere Solver](https://www.guballa.de/vigenere-solver): very good online **Vigenere Cipher solver** with bruteforce
- [Substitution Solver](https://www.guballa.de/substitution-solver): very good online **Substitution Cipher solver** with bruteforce
- [Sage Math](https://sagecell.sagemath.org/): online Sage environment to **perform Crypto calculations**
- [Crunch](https://tools.kali.org/password-attacks/crunch): Linux tool to **create custom dictionaries** for attacks (hash, pd, ..)
- [Online Hash Crack](https://www.onlinehashcrack.com/): big website to **perform hash/pwd cracking and identification** on various files
- [Hash Identifier](https://tools.kali.org/password-attacks/hash-identifier): Linux tool to **perform hash identification**
- [Morse Code Translator](https://morsecode.world/international/translator.html)
- [Dual Tone Decoder](http://dialabc.com/sound/detect/): find **DTMF tones** within audio clips
- [gmpy2](https://gmpy2.readthedocs.io/en/latest/intro.html): Python library for **multiple-precision arithmetic**
#### Resources
- [Weird Ciphers](http://www.quadibloc.com/crypto/intro.htm): a list of some **strange cryptography algorithms**
- [Symbolic Ciphers](https://www.dcode.fr/symbols-ciphers): another list of **strange cryptography algorithms**

## Steganography 🎨
#### Tools
- [Aperi'Solve](https://aperisolve.fr/): **one of the best online tools**, with static analysis and also running zsteg, steghide, exiftool, binwalk, foremost, .. 
- [StegOnline](https://stegonline.georgeom.net): big stego tool, upload image and **modify/extract data**
- [Stegsolve](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve): JAR file to view **hidden text in images**
- [Steg 1](https://stylesuxx.github.io/steganography/): online **encoder/decoder of files in images**
- [Steg 2](https://futureboy.us/stegano/decinput.html): online **encoder/decoder of files in images**, maybe more powerful
- [Images Color picker](https://imagecolorpicker.com/): get **colors from websites/images in Hex/RGB**
- [Stegseek](https://github.com/RickdeJager/stegseek): lightning fast **steghide cracker** that can be used to extract hidden data from files.
#### Resources
- [steghide](http://steghide.sourceforge.net/documentation/manpage.php): manual website of the **Steghide** tool
- [zsteg](https://github.com/zed-0xff/zsteg): Ruby tool for steganography purposes

## Web 🕸️
#### Tools
- [CSP Evaluator](https://csp-evaluator.withgoogle.com/): Google **CSP evaluator** with bypass possibilities
- [Subdomain Finder](https://subdomainfinder.c99.nl/index.php): website to **find subdomains of URLs**, even hidden ones
- [Google Certificates](https://transparencyreport.google.com/https/certificates): search certificates of a website by domain
- [Traversal Archives](https://github.com/jwilk/traversal-archives): samples of archive files in various formats that attempt to exploit (hypothetical) directory travesal bugs
#### Resources
- [CSP Cheatsheet](https://six2dez.gitbook.io/pentest-book/enumeration/web/csp): list of **CSPs and relative bypass** possibilities
- [JSONP Endpoints](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt): list of **well-known JSONP Endpoints**
- [Web Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings): list of **Web Payloads** of various techniques

## Pwn 🐛
### Tools
- [Syscall Reference](https://syscalls.w3challs.com/): **x86 / x64 syscalls manual** with registers value
- [Asm/Disasm](https://defuse.ca/online-x86-assembler.htm#disassembly): online **x86 / x64 assembler and disassembler**
- [LibC Check](https://libc.blukat.me/?q=puts%3A0x7f51bf2ee9c0&l=libc6_2.27-3ubuntu1_amd64): find all the **possible libc versions** with symbol name and entry address
- [BinaryNinja](https://cloud.binary.ninja/): online **binary file decompiler**
- [DogBolt](https://dogbolt.org/): online **binary file decompiler** with different options like Ghidra and BinaryNinja
### Resources

## Forensics 🕵️‍♂️
### Tools
- [Forensically](https://29a.ch/photo-forensics/#forensic-magnifier): **online forensic analysis tool** to extract cool data from images, .. 
- [Autopsy](https://www.sleuthkit.org/autopsy/): **file recovery tool** with data carving, ..
- [Foremost](https://tools.kali.org/forensics/foremost): **file recovery tool** based on their magic bytes, headers, ..
### Resources

## OSINT 🌐
- [Mail from LinkedIn](https://skrapp.io/tutorials/linkedin-email-finder): Chrome extension to **find email addresses from Linkedin page**
- [Wayback Machine](https://archive.org/web/): **webpage archive at a certain time**
- [Sherlock](https://github.com/sherlock-project/sherlock): hunt down **social media accounts by username**
- [Email lookup](https://epieos.com/): tool to **retrieve information linked to an email address**

## Reversing ↩️
### Tools
- [Online Decompiler](http://www.javadecompilers.com/): online tool to decompile **Java classes, APKs,...**
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF): tool to **decompile and reverse APK** files
- [JADX](https://github.com/skylot/jadx): tools for producing Java source code from **Android Dex and APK** files
- NB: strings is useful also on APK files
### Resources
