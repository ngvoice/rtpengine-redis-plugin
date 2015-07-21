IMPORTANT NOTE:
======================

**This plugin works for RTPEngine 4.1.x, not for earlier versions - Work in progress**

Installation Guide
======================

This plugin relies on some public functions that are part of the rtpengine project. Since this is mandatory, it's important to have an updated copy of rtpengine in a directory that is in the same level this plugin source code is, or in other words, in the same root directory both source trees are.

Example

<pre>
/main-directory/
  |-----rtpengine/
  |-----plugin/
</pre>

Clone the repo
<pre>
git clone https://github.com/ngvoice/rtpengine-redis-plugin rtpengine-redis-plugin -b 1and1-fmetz
cd rtpengine-redis-plugin
git clone https://github.com/1and1/rtpengine -b redis-dev
</pre>

Dependencies
======================

- hiredis, hiredis-devel, libevent-devel, redis (server)

Apart from that, this plugin uses the same dependency set that comes with rtpengine: glib2, openssl-devel, build-essential

Installation
======================
Go to plugin directory

<pre>
# cd plugin
</pre>

Compile it

<pre>
# make
</pre>

you should copy the resulting binary into the lib directory of rtpengine, usually by doing:
<pre>
# cp rtpengine-redis.so /usr/lib/rtpengine/rtpengine-redis.so
</pre>

in case the directory is missing, which is the case when installing rtpengine from the sources, you just need to create the directory and place the shared object into it.


Usage
======================
Use the -r parameter to specify the IP:port of Redis database, and -R to choose the database index to use

<pre>
rtpengine --table=0 --ip=192.168.3.101 --listen-ng=127.0.0.1:22222 --pidfile=/var/run/mediaproxy-ng.pid -r 127.0.0.1:6379 -R 0
</pre>

Considerations
======================
- Use "MONITOR" command to inspect what's going on the Redis server.
- If the plugin crashes, or you want to make a fresh restart, use "FLUSHALL" to wipe everything up and start with no data at all.



