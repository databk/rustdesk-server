## [1.1.1](https://github.com/databk/rustdesk-server/compare/1.1.0...1.1.1) (2026-10-25)


### Bug Fixes

* **ci:** replace broken docker-manifest-action with buildx imagetools ([#68](https://github.com/databk/rustdesk-server/issues/68)) ([5f61b04](https://github.com/databk/rustdesk-server/commit/5f61b04ebc10c5237daa186b3e2c6b8432313286))
* **hbbr:** normalize and validate management control URLs ([#73](https://github.com/databk/rustdesk-server/issues/73)) ([cd8538e](https://github.com/databk/rustdesk-server/commit/cd8538e8289d9b15db321a7e308012b521841dbf))
* **hbbr:** reject port 0 and empty port in control URL validation ([#75](https://github.com/databk/rustdesk-server/issues/75)) ([9a74649](https://github.com/databk/rustdesk-server/commit/9a74649bf85932c877fa8591c7d9fe5825e63af3)), closes [databk/rustdesk-server#73](https://github.com/databk/rustdesk-server/issues/73)



# [1.1.0](https://github.com/databk/rustdesk-server/compare/1.0.1...1.1.0) (2026-10-18)


### Bug Fixes

* add missing protobuf::Message and log imports after module split ([#39](https://github.com/databk/rustdesk-server/issues/39)) ([11c6802](https://github.com/databk/rustdesk-server/commit/11c680256b96cafee1b372ea7c73955b6c62e1fa)), closes [#38](https://github.com/databk/rustdesk-server/issues/38)
* **rendezvous:** support change-id pre-check for RegisterPk with empty pk ([#31](https://github.com/databk/rustdesk-server/issues/31)) ([4f9b845](https://github.com/databk/rustdesk-server/commit/4f9b845d7d880d6c33acacf4924bbf70b81d47a5))


### Features

* expose private management APIs for hbbs and hbbr ([#52](https://github.com/databk/rustdesk-server/issues/52)) ([c6c3929](https://github.com/databk/rustdesk-server/commit/c6c392941c863cd4d6ecfff949bb02116ffd98f3))
* forward WebRTC SDP and ICE candidates through rendezvous server ([#53](https://github.com/databk/rustdesk-server/issues/53)) ([07058e9](https://github.com/databk/rustdesk-server/commit/07058e9c64673f3657815008057984069010238c))
* **management:** add DELETE /v1/peers/:id to release a device id ([#66](https://github.com/databk/rustdesk-server/issues/66)) ([1295a8a](https://github.com/databk/rustdesk-server/commit/1295a8aa80965c0cf33f68fd9914aec6cef3fdaf))
* **management:** dynamic config updates, pending-restart reporting and in-memory logs ([#58](https://github.com/databk/rustdesk-server/issues/58)) ([5a86aba](https://github.com/databk/rustdesk-server/commit/5a86aba8c637bfd353b845ba319d13e25754c688))
* **management:** relay control channel, relay aggregation and SSE events ([#59](https://github.com/databk/rustdesk-server/issues/59)) ([5c843df](https://github.com/databk/rustdesk-server/commit/5c843dfcb5b2c952fdd352ce65959d29008f202a))
* **server:** support bind address, fix reg-timeout i32 overflow, refactor arg parsing ([#32](https://github.com/databk/rustdesk-server/issues/32)) ([0c03f64](https://github.com/databk/rustdesk-server/commit/0c03f647b45495ce3b870497585b7ccaedd393d2)), closes [#676](https://github.com/databk/rustdesk-server/issues/676) [#634](https://github.com/databk/rustdesk-server/issues/634) [#676](https://github.com/databk/rustdesk-server/issues/676)



## [1.0.1](https://github.com/databk/rustdesk-server/compare/1.0.0...1.0.1) (2026-08-14)


### Bug Fixes

* **rendezvous:** preserve peer port and handle WS heartbeat behind reverse proxy ([#27](https://github.com/databk/rustdesk-server/issues/27)) ([5da9290](https://github.com/databk/rustdesk-server/commit/5da9290c6c278573b59b1880bdc6fb4c7db90379)), closes [#26](https://github.com/databk/rustdesk-server/issues/26)



# [1.0.0](https://github.com/databk/rustdesk-server/compare/3b386b6b5486ed54a09994d1025ed8478127b029...1.0.0) (2026-06-12)


### Bug Fixes

* 127.0.0.1 is not loopback ([#515](https://github.com/databk/rustdesk-server/issues/515)) ([621da3c](https://github.com/databk/rustdesk-server/commit/621da3c8fe5d874d6516d191a267db5f1993e9b2))
* correct secure_tcp handshake and fallback to plain mode ([#8](https://github.com/databk/rustdesk-server/issues/8)) ([2258f2b](https://github.com/databk/rustdesk-server/commit/2258f2b0d5d183c512d7b8d8466842eda160d8a2))
* differentiate secure_tcp fallback logging by message type ([#10](https://github.com/databk/rustdesk-server/issues/10)) ([ed47401](https://github.com/databk/rustdesk-server/commit/ed4740111c6c68d47fff86783c978b8a7d12c462))
* **security:** update mio from 0.8.5 to 0.8.11 ([#633](https://github.com/databk/rustdesk-server/issues/633)) ([815c728](https://github.com/databk/rustdesk-server/commit/815c728837b8a091c9feeeabb423d543be3a7f8d))


### Features

* enable full peer registration and reachability over WebSocket ([#3](https://github.com/databk/rustdesk-server/issues/3)) ([54d0884](https://github.com/databk/rustdesk-server/commit/54d08849704d519de733a7724d3cd475d7aa4339))
* Publish container images to GitHub ghcr.io ([#473](https://github.com/databk/rustdesk-server/issues/473)) ([3b386b6](https://github.com/databk/rustdesk-server/commit/3b386b6b5486ed54a09994d1025ed8478127b029))
* support client disable-udp mode on server side ([#6](https://github.com/databk/rustdesk-server/issues/6)) ([96b2404](https://github.com/databk/rustdesk-server/commit/96b24047c5420ca0abe23270400928a86f26e950))


### Reverts

* Revert "chore(deps): update Cargo.lock (#11)" (#21) ([72b0de9](https://github.com/databk/rustdesk-server/commit/72b0de9a9640522546ea847de17e6472ebd0f891)), closes [#11](https://github.com/databk/rustdesk-server/issues/11) [#21](https://github.com/databk/rustdesk-server/issues/21)



