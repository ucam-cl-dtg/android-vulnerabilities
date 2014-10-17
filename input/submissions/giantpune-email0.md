Subject: updates for your list

From: giantpune <giantpune@gmail.com>

Date: 17/10/14 02:34

To: contact@androidvulnerabilities.org

Hi,

I'm contacting you about your list of android vulnerabilities.  I am the
one who found what became known as CVE-2012-4220/4221.  Your list looks
like it is missing a date for when it was discovered.  That was back in
April of 2012.  And it lists it as responsibly disclosed, but I feel that
is not accurate.  I originally contacted LG by telephone and email,
contacted Google's security team by email, and contacted Qualcomm via their
website.  Qualcomm's security team got back to me on 7/31/2012 and we
exchanged several emails and I helped them understand the issue.  They then
notified their customers (OEMs) and finally notified the general public via
their website.  Please change this status to reflect that the issue was
responsibly disclosed.

I have some other vulnerabilities which don't appear on your list.  There
is one I named lit which is a bug in the backlight driver for quite a few
LG phones.  I discovered this one around Occtober 2012.  After calling LG
and emailing them (and again getting no response), I disclosed it publicly
online.  Original public disclosure is here
http://androidforums.com/elite-all-things-root/638367-privilidge-escailation-exploit-in-lgs-backlight-driver.html
and
a package for rooting other models is here.
http://androidforums.com/l3-all-things-root/682486-root-apk-l38c.html .
This bug never got a CVE but it does affect at least 5 version of their
backlight driver which were used in an unknown number of phone models.

I also Identified a bug in LG's backdoor code in adbd.  They allow adbd to
run as root if a certain key file is present on the sd card.  However,
their key checking function was royally broken and creating a directory or
0-byte file was enough to trick them.  They later tried to fix it after
they saw us start to exploit it, but their fix was wrong and you could
still access the backdoor by getting only 1 byte of the key correct.  One
of the first phones this was released for was in January 2013.
http://forum.xda-developers.com/showthread.php?t=2094696  in this post, the
"adb shell touch /sdcard/g_security" command is creating the key as a file
of 0 bytes.  This bug also never got a CVE to my knowledge.

Thanks for your efforts

giantpune

