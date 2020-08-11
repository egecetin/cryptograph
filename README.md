# Cryptograph - An example of cryptography
 
 [![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fegecetin%2Fcryptograph)](https://hits.seeyoufarm.com)
 
 A cryptography example using Intel Integrated Performance Primitives (IPP) library.

## &#x1F53B;&#x1F53B;Important Notice!&#x1F53B;&#x1F53B;

This program has been developed only to share knowledge and experience. Please do not use it to store any sensitive data. Due to the nature of the cryptography, you will lose your data if you lose your key or in case of any program malfunction.
 
## Contents

* [General Info](#general-info)
* [Implemented Features](#implemented-features)
* [To do](#to-do)

## General Info

This project is developed for sharing knowledge and experience. General explanation of some cryptography methods can be found at [my Github site](https://egecetin.github.io/Projects/crypto.html).

Application is developed with following configuration

* Integrated Performance Primitives 2020.0.1
* Qt 5.14.2
* Windows SDK 10.0.17763.0

## Implemented Features

* Pre-compressing (Beware that [compressing of data can leak information](https://crypto.stackexchange.com/questions/29972/is-there-an-existing-cryptography-algorithm-method-that-both-encrypts-and-comp/29974#29974).)
  - LZSS
  - LZO
  - LZ4 (High Compression not implemented yet)
* Symmetric key cryptography algorithms
  - AES (256 bit only)
  - SM4 (256 bit only)
  
## To Do

* Directory and Multiple File support with a container output file
* Additional compressing algorithms
  - LZ4 High Compression
  - ZLIB
* Support for different key lengths in symmetric key algorithms
* Improvements to existing compression functions
* Asymmetric key cryptography algorithms
  - RSA
  - ECC
* Use C API instead of C++ classes (such as BigNumber)
* Process warnings and errors for Intel Compiler

