# NMOS Authorization API Implementation Changelog

## 1.0.9
- Allow clients to register using JSON in-line with RFC7591. Change imports in-line with Authlib v0.11 release.

## 1.0.8
- Pin versions of PyOpenSSL and Cryptography to force package upgrades.

## 1.0.7
- Add "authorize" button per client to lead to user authorization page. Alter styling.

## 1.0.6
- Fix Authorization endpoint.

## 1.0.5
- Add ability to load external config. Load static elements locally for running offline.

## 1.0.4
- Move NMOS packages from recommends to depends

## 1.0.3
- Update install instructions in README

## 1.0.2
- Decode bytes objects as string objects for python3 compatibility

## 1.0.1
- Alter cert endpoint to comply with RAML, pin gevent version to 1.2.2

## 1.0.0
- Initial Release
