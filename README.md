[![][kong-logo]][kong-url]

[![Build Status][badge-travis-image]][badge-travis-url]

Kong is a cloud-native, fast, scalable, and distributed Microservice
Abstraction Layer *(also known as an API Gateway, API Middleware or in some
cases Service Mesh)*. Made available as an open-source project in 2015, its
core values are high performance and extensibility.

Actively maintained, Kong is widely used in production at companies ranging
from startups to Global 5000 as well as government organizations.

[Installation](https://konghq.com/install) |
[Documentation](https://getkong.org/docs) |
[Forum](https://discuss.konghq.com) |
[Blog](https://konghq.com/blog) |
IRC (freenode): [#kong](http://webchat.freenode.net/?channels=kong) |
[Nightly Builds][kong-nightly-master]

## Summary

- [Summary](#summary)
- [Why Kong?](#why-kong)
- [Features](#features)
- [Distributions](#distributions)
- [Development](#development)
    - [Vagrant](#vagrant)
    - [Source Install](#source-install)
    - [Running for development](#running-for-development)
    - [Tests](#tests)
    - [Makefile](#makefile)
- [Enterprise Support & Demo](#enterprise-support--demo)
- [Overview Architecture based on kong](#overview-architecture-based-on-kong)
  - [Architecture](#architecture)
  - [Web timing diagram](#web-timing-diagram)
  - [In-house Web timing diagram](#in-house-web-timing-diagram)
  - [Design](#design)
    - [客户端请求用户服务进行登录,返回对应的 JWT 以及对应的『api path』](#客户端请求用户服务进行登录返回对应的-jwt-以及对应的api-path)
    - [应用 JWT 以及『api path』场景](#应用-jwt-以及api-path场景)
    - [客户端请求中 Token 承载方式](#客户端请求中-token-承载方式)
- [License](#license)

## Why Kong?

If you are building for web, mobile or IoT (Internet of Things) you will likely
end up needing common functionality to run your actual software. Kong can
help by acting as a gateway (or a sidecar) for microservices requests while
providing load balancing, logging, authentication, rate-limiting,
transformations, and more through plugins.

[![][kong-benefits]][kong-url]

## Features

- **Cloud-Native**: Platform agnostic, Kong can run from bare metal to
  Kubernetes.
- **Dynamic Load Balancing**: Load balance traffic across multiple upstream
  services.
- **Hash-based Load Balancing**: Load balance with consistent hashing/sticky
  sessions.
- **Circuit-Breaker**: Intelligent tracking of unhealthy upstream services.
- **Health Checks:** Active and passive monitoring of your upstream services.
- **Service Discovery**: Resolve SRV records in third-party DNS resolvers like
  Consul.
- **Serverless**: Invoke and secure AWS Lambda or OpenWhisk functions directly
  from Kong.
- **WebSockets**: Communicate to your upstream services via WebSockets.
- **OAuth2.0**: Easily add OAuth2.0 authentication to your APIs.
- **Logging**: Log requests and responses to your system over HTTP, TCP, UDP,
  or to disk.
- **Security**: ACL, Bot detection, whitelist/blacklist IPs, etc...
- **Syslog**: Logging to System log.
- **SSL**: Setup a Specific SSL Certificate for an underlying service or API.
- **Monitoring**: Live monitoring provides key load and performance server
  metrics.
- **Forward Proxy**: Make Kong connect to intermediary transparent HTTP proxies.
- **Authentications**: HMAC, JWT, Basic, and more.
- **Rate-limiting**: Block and throttle requests based on many variables.
- **Transformations**: Add, remove, or manipulate HTTP requests and responses.
- **Caching**: Cache and serve responses at the proxy layer.
- **CLI**: Control your Kong cluster from the command line.
- **REST API**: Kong can be operated with its RESTful API for maximum
  flexibility.
- **Geo-Replicated**: Configs are always up-to-date across different regions.
- **Failure Detection & Recovery**: Kong is unaffected if one of your Cassandra
  nodes goes down.
- **Clustering**: All Kong nodes auto-join the cluster keeping their config
  updated across nodes.
- **Scalability**: Distributed by nature, Kong scales horizontally by simply
  adding nodes.
- **Performance**: Kong handles load with ease by scaling and using NGINX at
  the core.
- **Plugins**: Extendable architecture for adding functionality to Kong and
  APIs.

For more info about plugins, you can check out the [Plugins
Hub](https://konghq.com/plugins/).

## Distributions

Kong comes in many shapes. While this repository contains its core's source
code, other repos are also under active development:

- [Kong Docker](https://github.com/Kong/docker-kong): A Dockerfile for
  running Kong in Docker.
- [Kong Packages](https://github.com/Kong/kong/releases): Pre-built packages
  for Debian, Red Hat, and OS X distributions (shipped with each release).
- [Kong Vagrant](https://github.com/Kong/kong-vagrant): A Vagrantfile for
  provisioning a development ready environment for Kong.
- [Kong Homebrew](https://github.com/Kong/homebrew-kong): Homebrew Formula
  for Kong.
- [Kong CloudFormation](https://github.com/Kong/kong-dist-cloudformation):
  Kong in a 1-click deployment for AWS EC2
- [Kong AWS AMI](https://aws.amazon.com/marketplace/pp/B014GHERVU): Kong AMI on
  the AWS Marketplace.
- [Kong on Microsoft Azure](https://github.com/Kong/kong-dist-azure): Run Kong
  using Azure Resource Manager.
- [Kong on Heroku](https://github.com/heroku/heroku-kong): Deploy Kong on
  Heroku in one click.
- [Kong and Instaclustr](https://www.instaclustr.com/solutions/managed-cassandra-for-kong/): Let
  Instaclustr manage your Cassandra cluster.
- [Nightly Builds][kong-nightly-master]: Builds of the master branch available
  every morning at about 9AM PST.

## Development

If you are planning on developing on Kong, you'll need a development
installation. The `next` branch holds the latest unreleased source code.

You can read more about writing your own plugins in the [Plugin Development
Guide](https://getkong.org/docs/latest/plugin-development/), or browse an
online version of Kong's source code documentation in the [Public Lua API
Reference](https://getkong.org/docs/latest/lua-reference/).

#### Vagrant

You can use a Vagrant box running Kong and Postgres that you can find at
[Kong/kong-vagrant](https://github.com/Kong/kong-vagrant).

#### Source Install

Kong mostly is an OpenResty application made of Lua source files, but also
requires some additional third-party dependencies. We recommend installing
those by following the source install instructions at
https://getkong.org/install/source/.

Instead of following the second step (Install Kong), clone this repository
and install the latest Lua sources instead of the currently released ones:

```shell
$ git clone https://github.com/Kong/kong
$ cd kong/

# you might want to switch to the development branch. See CONTRIBUTING.md
$ git checkout next

# install the Lua sources
$ luarocks make
```

#### Running for development

Check out the [development section](https://github.com/Kong/kong/blob/next/kong.conf.default#L244)
of the default configuration file for properties to tweak in order to ease
the development process for Kong.

Modifying the [`lua_package_path`](https://github.com/openresty/lua-nginx-module#lua_package_path)
and [`lua_package_cpath`](https://github.com/openresty/lua-nginx-module#lua_package_cpath)
directives will allow Kong to find your custom plugin's source code wherever it
might be in your system.

#### Tests

Install the development dependencies ([busted], [luacheck]) with:

```shell
$ make dev
```

Kong relies on three test suites using the [busted] testing library:

* Unit tests
* Integration tests, which require Postgres and Cassandra to be up and running
* Plugins tests, which require Postgres to be running

The first can simply be run after installing busted and running:

```
$ make test
```

However, the integration and plugins tests will spawn a Kong instance and
perform their tests against it. As so, consult/edit the `spec/kong_tests.conf`
configuration file to make your test instance point to your Postgres/Cassandra
servers, depending on your needs.

You can run the integration tests (assuming **both** Postgres and Cassandra are
running and configured according to `spec/kong_tests.conf`) with:

```
$ make test-integration
```

And the plugins tests with:

```
$ make test-plugins
```

Finally, all suites can be run at once by simply using:

```
$ make test-all
```

Consult the [run_tests.sh](.ci/run_tests.sh) script for a more advanced example
usage of the tests suites and the Makefile.

Finally, a very useful tool in Lua development (as with many other dynamic
languages) is performing static linting of your code. You can use [luacheck]
\(installed with `make dev`\) for this:

```
$ make lint
```

#### Makefile

When developing, you can use the `Makefile` for doing the following operations:

|               Name | Description                                        |
| -----------------: | -------------------------------------------------- |
|          `install` | Install the Kong luarock globally                  |
|              `dev` | Install development dependencies                   |
|             `lint` | Lint Lua files in `kong/` and `spec/`              |
|             `test` | Run the unit tests suite                           |
| `test-integration` | Run the integration tests suite                    |
|     `test-plugins` | Run the plugins test suite                         |
|         `test-all` | Run all unit + integration + plugins tests at once |

## Enterprise Support & Demo

If you are working in a large organization you should learn more about [Kong
Enterprise](https://konghq.com/kong-enterprise-edition/).

## Overview Architecture based on kong 
### Architecture
[![][saas-architecture]][Management system SAAS/Local Architecture]

### Web timing diagram
[![][jwt-timing]][web jwt timing diagram]

### In-house Web timing diagram
[![][jwt-inhouse-timing]][in house jwt timing diagram]

### Design
#### 客户端请求用户服务进行登录,返回对应的 JWT 以及对应的『api path』

1. 登录验证（`Kong 判断请求为 POST 提交登录接口则直接放行，不进行 JWT 验证，且登录接口不应受限于 『api path』鉴权`）。
2. 通过登录验证后，服务签发（设置 Cookie）JWT（参考：http://jwtbuilder.jamiekurtz.com/），同时返回用户信息，用户信息中也包含了 JWT，可以用于不方便处理 setcookie Response 的地方
```json
//JWT payload 部分的必要信息
{
    iss: 签发服务从 Kong 得到的签发者ID，同时得到的还有 secret，用于 JWT 签名
    iat：签发时间，时间戳
    exp：失效时间，时间戳
    client_type: 1 = 普通用户| 2 = 内部用户| 3 = 系统用户
    app_key: 预签发的 JWT 中为随机字符串(2,3 用户类型)，普通用户为 null
    extra:{ // 预签发的 JWT 中为空数组
        tenant_id: 租户ID
        user_id: 用户ID
        ...
    }
}
```  
3. 通过登录验证后，请求 /inno-user/user/v1/user/getUserApiPath 接口将返回给客户端 JSON 格式的『api path』
```
{
  "exp" : 47123100000,
  "apis" : {
      "GETxxx" : {
        "url" : "xxx",
        "summary": "Get something",
        "token" : "xxx",
        "method" : "POST"
      },
      "GETinno-user\/user\/users" : {
        "url" : "inno-user\/user\/users",
        "summary": "Get users",
        "token" : "xxxxxxx",
        "method" : "GET"
      },
      "GETinno-user\/user\/users\/{id}" : {
        "url" : "inno-user\/user\/users\/{id}",
        "summary": "Get user",
        "token" : "xxxxxxx",
        "method" : "GET"
      }
  }
}
```
   
token 生成规则： sha1(服务划分名称 + 具体服务 + 服务内路由取固定值 + Http Method（大写）+ URL 的 path 层级数量 + md5(用户id + 租户id + 固定salt + jwt签发时间iat)) 

举个例子：
```
inno-user             /              user            /            users            /            :id            /            fee            /            :id         <----------------- 目录分隔符隔开的 path 层级为 6

服务划分名称                  具体服务                      固定值                       动态值                   固定值                   动态值
```

示例：
```
1. URL: inno-data/fee/fees/:id 
   Method: GET
   token: sha1(inno-data + fee + fees + GET + 4 + md5(user_id + tenant_id + salt + iat)) 

2. URL: inno-data/patent/patents/:id/fee 
   Method: GET
   token: sha1(inno-data + patent + patents + fee + GET + 5 + md5(user_id + tenant_id + salt + iat)) 

3. URL: inno-data/patent/patents/:id/fee/:id 
   Method: GET
   token: sha1(inno-data + patent + patents + fee + GET + 6 + md5(user_id + tenant_id + salt + iat))
```

#### 应用 JWT 以及『api path』场景
- 场景1：客户端请求某个后台服务

  1. 客户端经过登录后得到 JWT 和『api path』，将 JWT 放入 Cookie / Header / GET 中，API Token 作为 API 的 GET 参数进行请求发送
  2. Kong 通过从 Cookie / Header / GET 参数获取 JWT 进行验证是否是有效合法的 JWT
  3. Kong 通过请求 URL 中的 token GET 参数进行验证是否当前用户有权限访问

- 场景2：后台服务1 主动请求 后台服务2
  
  1. Token 签发服务预留系统用户账号，调用方服务需保存签发服务的相关配置（地址，账户等），后台服务使用预留的内部用户账号获取到 JWT，将 JWT 放入 Cookie / Header / GET 中进行请求发送
  2. 内部服务无须 API Token
  3. Kong 通过 Cookie / Header / GET 参数获取 JWT，解析得到客户端类型为内部用户，则跳过『api path』鉴权，直接进行转发

- 场景3：本地 SAAS 内部部署服务（或者第三方系统）请求广域网 SASS 功能后台服务（如费用同步服务）
  
  1. Token 签发服务预留内部用户账号，调用方服务需保存签发服务的相关配置（地址，账户等），本地 SAAS 内部部署服务（或者第三方系统）使用预留的系统用户账号获取到 JWT，将 JWT 放入 Cookie / Header / GET 中进行请求发送
  2. 系统服务无须 API Token「存疑」
  3. Kong 通过 Cookie / Header / GET 参数获取 JWT，解析得到客户端类型为系统用户，则跳过『api path』鉴权，直接进行转发

#### 客户端请求中 Token 承载方式
**JWT（优先级越小越优先，Kong 优先读取优先级最高的可用 JWT）：**

1. Cookie 优先级 1
```
Cookie：Authorization=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhMzZjMzA0OWIzNjI0OWEzYzlmODg5MWNiMT.AhumfY35GFLuEEjrOXiaADo7Ae6gt_8VLwX7qffhQN4; OtherCookie=xxxxxxx
```
2. Header 优先级 2
```
Authorization: Bearer xxxxxxxxxxxxxxxxxxx
示例 Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJhMzZjMzA0OWIzNjI0OWEzYzlmODg5MWNiMT.AhumfY35GFLuEEjrOXiaADo7Ae6gt_8VLwX7qffhQN4
```

**API Token**
1. Header
```
X-API-Token=ZjMzA0OWIzNjI0OWEzYzlmODg5MWNiMTI
```

## License

```
Copyright 2016-2018 Kong Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

[kong-url]: https://konghq.com/
[kong-logo]: https://konghq.com/wp-content/uploads/2018/05/kong-logo-github-readme.png
[kong-benefits]: https://konghq.com/wp-content/uploads/2018/05/kong-benefits-github-readme.png
[kong-nightly-master]: https://bintray.com/kong/kong-community-edition-nightly/kong-master
[badge-travis-url]: https://travis-ci.org/Kong/kong/branches
[badge-travis-image]: https://travis-ci.org/Kong/kong.svg?branch=master

[busted]: https://github.com/Olivine-Labs/busted
[luacheck]: https://github.com/mpeterv/luacheck
[saas-architecture]: https://raw.githubusercontent.com/icyxp/kong/feat/0.14.1/assets/images/saas.jpeg
[jwt-timing]: https://raw.githubusercontent.com/icyxp/kong/feat/0.14.1/assets/images/jwt.jpeg
[jwt-inhouse-timing]: https://raw.githubusercontent.com/icyxp/kong/feat/0.14.1/assets/images/jwt-inhouse.jpeg