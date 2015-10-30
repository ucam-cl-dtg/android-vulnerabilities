
title: Home
menu-position: 0
first-section-id: scores
---
<div class="four columns info">
<h2>Scores out of ten</h2>
{{score_table(['input/scores/sec_scores_summary.csv', 'input/scores/sec_scores_manufacturer.csv'], ['other','non-Nexus devices'])}}
</div>
<div class="eight columns right-cols">
<h2>Calculating the score</h2>
<p>We developed the FUM score to compare the security provided by different device manufacturers.
The score gives each Android manufacturer a score out of 10 based on the security they have provided to their customers over the last four years.</p>
<p style="margin-bottom:0px"> The score has three components:</p>
<dl class="lining">
<dt><b><i>f</i></b></dt> <dd>the proportion of devices free from known critical vulnerabilities.</dd>
<dt><b><i>u</i></b></dt> <dd>the proportion of devices updated to the most recent version.</dd>
<dt><b><i>m</i></b></dt> <dd>the number of vulnerabilities the manufacturer has not yet fixed on any device.</dd>
</dl>
<p><a href="scores">Further details</a>.</p>
</div>
</div>
</section>
<section id="stats" style="background:#fff;">
<div class="row">
<div class="twelve columns" style="padding-top:15px">
 <h2>Proportion of devices running vulnerable versions of Android</h2>
 <div style="width:100%; margin:auto;">
 <a href="graph">
 {% insert_svg('images/norm_versionsecurity', 'Proportion of devices affected by critical vulnerabilities', '720px', '360px', link=True)  %}
 </a></div>
 <p style="text-align: left;">This figure shows our estimate of the proportion of Android devices running <em>insecure</em>, <em>maybe secure</em> and <em>secure</em> versions of Android over time.
Further details on how this figure constructed can be found <a href="graph">on a separate page</a>.
 </p>
</div>
</div>
</section>
<section id="da" class="textured" markdown="1">
<div class="row" markdown="1">
<div class="row">
 <div class="three columns">
  <a href="https://play.google.com/store/apps/details?id=uk.ac.cam.deviceanalyzer" style="max-width:300px; margin:auto;">{% insert_svg('images/da-logo', 'Device Analyzer logo','100%','auto', link=True)%}</a>
 </div>
 <div class="nine columns">
 <h2>Help us, install <a href="https://play.google.com/store/apps/details?id=uk.ac.cam.deviceanalyzer">Device Analyzer</a></h2>
 <p>We are only able to produce these scores due to the contributions made to <a href="https://deviceanalyzer.cl.cam.ac.uk/">Device Analyzer</a> by members of the public.
If you have an Android device you can install the <a href="https://play.google.com/store/apps/details?id=uk.ac.cam.deviceanalyzer">Device Analyzer app</a> and provide researchers with additional data on which devices are secure.
Device Analyzer follows <a href="http://deviceanalyzer.cl.cam.ac.uk/collected.htm">best practices in privacy preservation</a>.</p>
 <p>If you have information about a vulnerability not listed on this site then you can <a href="submit">submit it</a>.</p>
 <p>If you have MDM data and want to know which devices used by your organisation are vulnerable then we can help: <a href="#contact">contact us</a>.</p>
 </div>
</div>
</div>
</section>
<section markdown="1" style="background:#fff;" id="vulnerabilities">
<div class="row" markdown="1">

## Vulnerabilities and papers

We are collating all critical vulnerabilities in Android and storing this information in a [machine readable format (json)](spec).
We are only tracking critical vulnerabilities which an app could exploit.
These are vulnerabilities that allow an app (malicious or compromised) to either gain root or gain privileges which can then be used to obtain root.

<div class="row" markdown="1">
<div class="four columns" markdown="1">

### List of vulnerabilities
* [All vunerabilities](all)
* [By manufacturer](by/manufacturer)
* [By year](by/year)
* [By Android version](by/version)
* [By submitter](by/submitter)
* [By category](by/category)

</div>
<div class="eight columns" markdown="1">

### Published papers

 * [Security metrics for the Android ecosystem](https://www.cl.cam.ac.uk/~drt24/papers/spsm-scoring.pdf) by Daniel R. Thomas, Alastair R. Beresford and Andrew Rice in ACM CCS Workshop on Security and Privacy in Smartphones and Mobile Devices (SPSM) 2015
 * [The lifetime of Android API vulnerabilities: case study on the JavaScript-to-Java interface](https://www.cl.cam.ac.uk/~drt24/papers/spw15-07-Thomas.pdf) by Daniel R. Thomas, Alastair R. Beresford, Thomas Coudray, Tom Sutcliffe and Adrian Taylor in the Proceedings of the Security Protocols Workshop 2015

### Press releases

 * [Thursday 8th October 2015](press/2015-10-08): 87% of Android devices insecure - Manufacturers fail to provide security updates
 * [Light Blue Touchpaper](https://www.lightbluetouchpaper.org/2015/10/08/87-of-android-devices-insecure-because-manufacturers-fail-to-provide-security-updates/): 87% of Android devices insecure because manufacturers fail to provide security updates

</div></div><div class="row" markdown="1"><div class="twelve columns" markdown="1">

### Press coverage

 * [ZDNet](http://www.zdnet.com/article/android-security-a-market-for-lemons-that-leaves-87-percent-insecure/): Android security a 'market for lemons' that leaves 87 percent vulnerable
 * [Arstechnica](http://arstechnica.com/security/2015/10/university-of-cambridge-study-finds-87-of-android-devices-are-insecure/): University of Cambridge study finds 87% of Android devices are insecure
 * [The Register](http://www.theregister.co.uk/2015/10/12/android_patching_survey/): Android users left at risk... and it's not even THEIR FAULT this time!
 * [Silicon Angle](http://siliconangle.com/blog/2015/10/14/the-elephant-in-the-room-study-confirms-android-devices-vulnerable-due-to-lack-of-patches/): The elephant in the room: Study confirms Android devices vulnerable due to lack of patches
 * [Phone arena](http://www.phonearena.com/news/Cambridge-paper-shows-that-LG-is-better-than-other-OEMs-when-it-comes-to-security_id74681): Cambridge paper shows that LG is better than other OEMs when it comes to security
 * [Digital Journal](http://www.digitaljournal.com/technology/90-of-android-devices-left-exposed-to-critical-vulnerabilities/article/446449): 90% of Android devices left exposed to critical vulnerabilities
 * [The Sydney Morning Herald](http://www.smh.com.au/digital-life/consumer-security/9outof10-android-phones-are-insecure-and-manufacturers-are-to-blame-20151014-gk8kp5.html): 9-out-of-10 Android phones are insecure, and manufacturers are to blame
 * [Digital Trends](http://www.digitaltrends.com/mobile/android-security-report/): "Google-commissioned security report paints a bleak picture of Android" (Note: Google did not commission this report, they funded work on Device Analyzer which we used in this analysis)
 * [Silicon Republic](https://www.siliconrepublic.com/enterprise/2015/10/14/87pc-of-android-devices-wildly-insecure-report): 87pc of Android devices wildly insecure — report
 * [Forbes](http://www.forbes.com/sites/ewanspence/2015/10/14/android-vulnerability-university-study/): The Dangerous Vulnerabilities Hiding In The Heart Of Android
 * [Gadgets 360](http://gadgets.ndtv.com/mobiles/news/lg-top-oem-for-issuing-security-patches-to-its-android-devices-report-752483): LG Top OEM for Issuing Security Patches to Its Android Devices: Report
 * [Android Headlines](http://www.androidheadlines.com/2015/10/ah-primetime-cambridge-university-analyze-android-security-risk.html): AH Primetime: Cambridge University Analyze Android Security Risk
 * [Engadget](http://www.engadget.com/2015/10/14/android-vulnerabilities/): Most Android phones are vulnerable due to lack of security patches
 * [Threatpost](https://threatpost.com/researchers-find-85-percent-of-android-devices-insecure/115030/): Researchers Find 85 Percent of Android Devices Insecure
 * [Guardian](http://www.theguardian.com/commentisfree/2015/oct/18/were-all-casualties-holy-war-android-security-apple-john-naughton): Security is the loser in the holy war between Android and Apple

</div>
</div>
</div>
</section>
<section class="textured" id="contact">
<div class="row">
<div class="row">
 <div class="four columns info">
<h2>Contact</h2>
  <p>Computer Laboratory<br/>University of Cambridge<br/>15 JJ Thompson Avenue<br/>Cambridge CB3 0FD<br/>
  <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#99;&#111;&#110;&#116;&#97;&#99;&#116;&#64;&#97;&#110;&#100;&#114;&#111;&#105;&#100;&#118;&#117;&#108;&#110;&#101;&#114;&#97;&#98;&#105;&#108;&#105;&#116;&#105;&#101;&#115;&#46;&#111;&#114;&#103;">&#99;&#111;&#110;&#116;&#97;&#99;&#116;&#64;&#97;&#110;&#100;&#114;&#111;&#105;&#100;&#118;&#117;&#108;&#110;&#101;&#114;&#97;&#98;&#105;&#108;&#105;&#116;&#105;&#101;&#115;&#46;&#111;&#114;&#103;</a>
</p>
 </div>
 <div class="eight columns right-cols">
  <div class="row">
   <div class="twelve columns">
   <h2>Researchers</h2>
   </div>
   <div class="three columns" style="margin:auto; text-align:center;">
    <a href="https://www.cl.cam.ac.uk/~drt24/"><img src="images/people/drt24.jpg" alt="Picture of Daniel Thomas"/></a>
    <p><a href="https://www.cl.cam.ac.uk/~drt24/">Daniel Thomas</a></p>
   </div>
   <div class="three columns" style="margin:auto; text-align:center;">
    <a href="https://www.cl.cam.ac.uk/~arb33/"><img src="images/people/arb33.jpg" alt="Picture of Alastair Beresford"/></a>
    <p><a href="https://www.cl.cam.ac.uk/~arb33/">Alastair Beresford</a></p>
   </div>
   <div class="three columns" style="margin:auto; text-align:center;">
    <a href="https://www.cl.cam.ac.uk/~acr31/"><img src="images/people/acr31.jpg" alt="Picture of Andrew Rice"/></a>
    <p><a href="https://www.cl.cam.ac.uk/~acr31/">Andrew Rice</a></p>
   </div>
   <div class="three columns" style="margin:auto; text-align:center;">
    <a href="https://github.com/danieltwagner"><img src="images/people/dtw30.jpg" alt="Picture of Daniel Wagner"/></a>
    <p><a href="https://github.com/danieltwagner">Daniel Wagner</a></p>
   </div>
  </div> <!-- Nested Row End -->
 </div>
</div>
