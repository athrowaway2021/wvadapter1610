# wvadapter1610
Tool to perform modular exponentiation with the private key in a WidevineCDM library on arbitrary data provided by the user. The data must be exactly 256 bytes/2048 bits but can be padded with zeroes. Only works with the 1610 version of the library.

Usage:
```
> wvadapter [hex-formatted data] [path to cdm library]
```
```
> wvadapter 48ce88d1f8f4dcc348b160595142c84e2f2ad3fae20f009222ba58e4a40f6c09209f1b16d1ed9d2aca346051c2abccca946af11f16d23159cfc585dd78a5d45a385844124a7744a1d62af19b2468e903338dfbbbd702c30d864e5a2bdf474c96bd13a94de6d0603c940f0830b25f8da936ef5dd32d7c7f0ff4c99842c2199d16ccf23796c27bd1d15816b4644e517ccb98d40c329fafa499fa39b5d27775a2c636f72abb1de03b2b39ca0dbf7c56992c0c605b6e23a59536f1fb073894966feec44e0bbfb990ee190c1302962f04c0f785dd73c8cf68039d7185b23a97d678ed4f94030d752011a279e7c72db8ed70a241dbdd47f46a9ac70a23029daebf3bc6 ../widevinecdm.dll
19ded36a30b83dfdec210a1f39c9f4ea08ee0f611bcb8fa057ccf8dd741124eca3c415d125d66df2c73bf5e12fb63b7e7346788ca0fd54852e849a3b0dc7105ff6040d7404155a52774b977e399bcfe6eb6bed11c6d2cb5cb0d1586ba327c69488c0fa5f19cbd79a8fa4327d0f874c8f99769d9e3c058e04b1ae91108c9135753d11acf9b4056c62ba2c4e557317826435f4181e05d3c1070d4689ebc882f068190305f58f731a12ba4c80c98d82c446dcdec3a4cd725ea263e212f8815de54049c6ed312b3d2d409188714e649045b6c71f9b1fc62b9eb2102dd40c75065068b0e4be7d9fe7d7ec74638b01c76727dbee24574d003fb2c2e5fa86f2f025bbd1
```

Works by replacing code at a fixed address in the library to load our data instead of a hash during the license request signing process, resulting in the signature field being replaced with our data exponentiated by the private key. This gives us a primitive that can be then extended for signing or decrypting by wrapping it with PSS or OAEP scheme respectively. I would love to do a writeup for this but it's been more than a year since I wrote this D:

Releasing since the key is now revoked and this was a rather fun project. This method is universal, is practically much easier than extracting the private key itself, and could be replicated for any previous or future version of the library if you have the time to find out where the whiteboxed signing procedure is in the library, although it's not difficult with a modicum of reverse engineering experience.
