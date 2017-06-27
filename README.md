<img src="public/images/logowps.png"  width="200px" height="200px"/>

> A WebSniffer for tcp connections attemps, detect connections to closed ports



## About Websniffer

Websniffer detect connections throw rawsockets, decode the information in server and send the notifies to the client with Websockets.
The code is inspired in [PortDog](https://github.com/puniaze/PortDog)


## Install

```bash
  $ git clone git@github.com:ericsuarez/WebSniffer.git
  $ cd WebSniffer
  $ npm i 
  $ sudo npm start
```

## Disclaimer

The display of connections attemps has a delay and probably some connections are lost because if WebSniffer print all the connections (WebSocket -> 8080 include) the browser crash :).

## DEMO

![WebSn](webso.gif)
