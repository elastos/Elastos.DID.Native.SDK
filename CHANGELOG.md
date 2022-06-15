06/15/2022 Chen Yu chenyu_kaola@126.com Version 2.2.1, new version of DID SDK has main change as follow:
- Support to set skew seconds for jwt parser.
- Support http redirect.
- Add the interface to free the memory.
- Fix some bugs.

04/06/2022 Chen Yu chenyu_kaola@126.com Version 2.2.0, new version of DID SDK has main change as follow:
- Support JSON-LD context.
- Improve the DID objects validity check.
- Normalize the serialized output to NFC form.
- Fix some bugs.

12/06/2021 Chen Yu chenyu_kaola@126.com Version 2.1.5, new version of DID SDK has main change as follow:
- Normalize the wordlist files.
- Add optional unicode normalization support.

12/01/2021 Chen Yu chenyu_kaola@126.com Version 2.1.4, new version of DID SDK has main change as follow:
- Add the method to synchnorize for DIDStore.
- Modify the id chain request.
- Fix some bugs.

10/18/2021 Chen Yu chenyu_kaola@126.com Version 2.1.3, new version of DID SDK has main change as follow:
- Modify the method to support certificate verification on Windows
- Support ARM mode.
- Auto select the best resolver.
- Fix some bugs.

08/06/2021 Chen Yu chenyu_kaola@126.com Version 2.1.2, new version of DID SDK has main change as follow:
- Support certificate verification on Windows


07/16/2021 Chen Yu chenyu_kaola@126.com Version 2.1.1, new version of DID SDK has main change as follow:
- Add more detail log for DID objects verification
- Fix some bugs.

07/06/2021 Chen Yu chenyu_kaola@126.com Version 2.1.0, the second version of DID SDK, DID 2.0 SDK new features:

- Customized DID, user can choose their DID identifiers
- New method to declare or revoke credentials to the ID chain
- New method to transfer Customized DID
- Many internal improvements
- Backward compatible support for DID 1.x SDK



07/21/2020 Chen Yu chenyu_kaola@126.com Version 1.0, the first version of DID SDK, main points listed:

- DID: DID is a globally unique identifier that does not require a centralized registration authority.
- DIDDocument: This is the concrete serialization of the data model, according to a particular syntax.
- Credential: Credential is a set of one or more claims made by the same entity.
- Presentation: A Presentation can be targeted to a specific verifier by using a Linked Data Proof that includes a nonce and realm.
- DIDStore: DIDStore is local store for specified DID.

09/23/2020 Chen Yu chenyu_kaola@126.com Version 1.1, main points listed:

- Support Windows version.
- Add new Python cffi module.
- Generate the export symbols automatically.
- Add validater tool to prove doc or credential.
- Fix some bugs and improve some flows.

10/27/2020 Chen Yu chenyu_kaola@126.com Version 1.2, main points listed:

- Update python cffi module compile with Xcode 12.
- Support seperating JWT from DID SDk.
- Use findjava variables in JNI adapter CMake file.
- Compatible the oldest version.
- Fix some bugs and improve some flows.
