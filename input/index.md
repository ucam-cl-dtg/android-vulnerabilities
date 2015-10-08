
title: Home
menu-position: 0
---
<div id="row">
<div class="four columns info" id="scores">
<h2>Scores out of ten</h2>
<table class="five" >
<tbody>
<tr><td>Nexus&nbsp;devices&nbsp;</td>  <td>5.2&nbsp;<i>(best)</i></td></tr>
<tr><td>{{link_manufacturer('LG')}}</td> <td>4.0</td></tr>
<tr><td>{{link_manufacturer('Motorola')}}</td>   <td>3.1</td></tr>
<tr><td>{{link_manufacturer('Samsung')}}</td>    <td>2.7</td></tr>
<tr><td>{{link_manufacturer('Sony')}}</td>   <td>2.5</td></tr>
<tr><td>{{link_manufacturer('HTC')}}</td>    <td>2.5</td></tr>
<tr><td>{{link_manufacturer('Asus')}}</td>   <td>2.4</td></tr>
<tr><td>{{link_manufacturer('Alps')}}</td>   <td>0.7</td></tr>
<tr><td>{{link_manufacturer('Symphony')}}</td>   <td>0.3</td></tr>
<tr><td>{{link_manufacturer('Walton')}}</td> <td>0.3&nbsp;<i>(worst)</i></td></tr>
</tbody>
</table>
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
<!--<div class="six columns">
{% insert_svg('images/fum', 'FUM score = 4 cdot f + 3 cdot u + 3 cdot {{2} over {1+e^m} }','100%','100%') %}
</div>-->
</div>
</div>

</section>
<section style="background:#fff;">
<div class="row"
<div id="stats" class="twelve columns" style="padding-top:15px">
 <h2>Proportion of devices running vulnerable versions of Android</h2>
 <div style="width:100%; margin:auto;">
 {% insert_svg('images/norm_versionsecurity', 'Proportion of devices affected by critical vulnerabilities', '720px', '360px')  %}
 </div>
 <p style="text-align: left;">This figure shows our estimate of the proportion of Android devices running <em>insecure</em>, <em>maybe secure</em> and <em>secure</em> versions of Android over time.
Further details on how this figure constructed can be found <a href="graph" style="font-weight:bold;">on a separate page</a>.
 </p>
</div>
</div>
</section>
<section id="screenshots" markdown="1">
<div class="row" markdown="1" id="da">

<div class="row">
 <div class="three columns">
  <a href="https://play.google.com/store/apps/details?id=uk.ac.cam.deviceanalyzer">{% insert_svg('images/da-logo', 'Device Analyzer logo','100%','auto', link=True)%}</a>
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

We are collating all critical vulnerabilities in Android and storing this information in a [machine reable format (json)](spec).
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

</div>
</div>

</div>
</section>
<section markdown="1" id="screenshots">
<div id="contact" class="row" markdown="1">

<div class="row">
 <div class="four columns info">
<h2>Contact</h2>
  <p>Computer Laboratory<br/>University of Cambridge<br/>15 JJ Thompson Avenue<br/>Cambridge CB3 0FD<br/>
  <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#99;&#111;&#110;&#116;&#97;&#99;&#116;&#64;&#97;&#110;&#100;&#114;&#111;&#105;&#100;&#118;&#117;&#108;&#110;&#101;&#114;&#97;&#98;&#105;&#108;&#105;&#116;&#105;&#101;&#115;&#46;&#111;&#114;&#103;">&#99;&#111;&#110;&#116;&#97;&#99;&#116;&#64;&#97;&#110;&#100;&#114;&#111;&#105;&#100;&#118;&#117;&#108;&#110;&#101;&#114;&#97;&#98;&#105;&#108;&#105;&#116;&#105;&#101;&#115;&#46;&#111;&#114;&#103;</a>
</p>
 </div>

 <div class="eight columns right-cols">
  <div class="row">
   <h2>Researchers</h2>
   <div class="four columns">
    <a href="https://www.cl.cam.ac.uk/~drt24/"><img src="images/people/drt24.jpg" alt="Picture of Daniel Thomas"/></a>
    <p><a href="https://www.cl.cam.ac.uk/~drt24/">Daniel Thomas</a></p>
   </div>

   <div class="four columns">
    <a href="https://www.cl.cam.ac.uk/~arb33/"><img src="images/people/arb33.jpg" alt="Picture of Alastair Beresford"/></a>
    <p><a href="https://www.cl.cam.ac.uk/~arb33/">Alastair Beresford</a></p>
   </div>

   <div class="four columns">
    <a href="https://www.cl.cam.ac.uk/~acr31/"><img src="images/people/acr31.jpg" alt="Picture of Andrew Rice"/></a>
    <p><a href="https://www.cl.cam.ac.uk/~acr31/">Andrew Rice</a></p>
   </div>
<!--
   <div class="eight columns">
    <a href="https://github.com/danieltwagner"><img src="images/people/dtw30.jpg" alt="Picture of Daniel Wagner"/></a>
    <p><a href="https://github.com/danieltwagner">Daniel Wagner</a></p>
   </div>
-->
  </div> <!-- Nested Row End -->
 </div>
</div>
