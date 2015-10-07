
title: Home
menu-position: 0
---
<div id="row">
<div class="five columns info" id="scores">
<h3 style="text-align: center">FUM scores for manufacturers and Nexus devices.</h3>
<table class="five" style="margin:auto;">
<tbody>
<tr><th>Name</th>   <th>FUM score</th>
<tr><th></th>   <th> (out of 10)</th></tr>
<tr><td>Nexus</td>  <td>5.21</td></tr>
<tr><td>{{link_manufacturer('LG')}}</td> <td>4.06</td></tr>
<tr><td>{{link_manufacturer('Motorola')}}</td>   <td>3.08</td></tr>
<tr><td>{{link_manufacturer('Samsung')}}</td>    <td>2.68</td></tr>
<tr><td>{{link_manufacturer('Sony')}}</td>   <td>2.46</td></tr>
<tr><td>{{link_manufacturer('HTC')}}</td>    <td>2.46</td></tr>
<tr><td>{{link_manufacturer('Asus')}}</td>   <td>2.36</td></tr>
<tr><td>{{link_manufacturer('other')}}</td>  <td>1.84</td></tr>
<tr><td>{{link_manufacturer('alps')}}</td>   <td>0.73</td></tr>
<tr><td>{{link_manufacturer('Symphony')}}</td>   <td>0.30</td></tr>
<tr><td>{{link_manufacturer('walton')}}</td> <td>0.26</td></tr>
</tbody>
</table>
</div>
<div class="seven columns right-cols">
<h2>The FUM score</h2>
<p>It is hard to comapre the security provided by different device manufacturers but the FUM score gives each Android manufacturer a score out of 10 based on the security they provide to their customers.<br/>
The FUM score has three components:</p>
<dl class="lining">
<dt><i>f</i></dt> <dd>the proportion of devices free from known critical vulnerabilities.</dd>
<dt><i>u</i></dt> <dd>the proportion of devices updated to the most recent version.</dd>
<dt><i>m</i></dt> <dd>the number of vulnerabilities the manufacturer has not yet fixed on any device.</dd>
</dl>

{% insert_svg('images/fum', 'FUM score = 4 cdot f + 3 cdot u + 3 cdot {{2} over {1+e^m} }','100%','100%') %}
</div>
</div>
<div id="stats" class="row twelve columns" id="graph" style="padding-top:15px">
 <h2>Proportion of devices running vulnerable versions of Android</h2>
 <div style="width:100%; margin:auto;">
 {% insert_svg('images/norm_versionsecurity', 'Proportion of devices affected by critical vulnerabilities', '720px', '360px')  %}
 </div>
 <p>This figure shows our estimate of the proportion of Android devices running <em>insecure</em>, <em>maybe secure</em> and <em>secure</em> versions of Android over time.
<a href="graph">More details</a>.
 </p>
</div>

<div class="row">
 <div class="three columns">
  <a href="https://play.google.com/store/apps/details?id=uk.ac.cam.deviceanalyzer">{% insert_svg('images/da-logo', 'Device Analyzer logo','100%','auto', link=True)%}</a>
 </div>
 <div class="nine columns">
 <h2 id="da">Help us</h2>
 <p>We are only able to produce these scores due to the contributions made to <a href="https://deviceanalyzer.cl.cam.ac.uk/">Device Analyzer</a> by members of the public.
If you have an Android device you can install the <a href="https://play.google.com/store/apps/details?id=uk.ac.cam.deviceanalyzer">Device Analyzer app</a> and provide researchers with additional data on which devices are secure.
Device Analyzer follows <a href="http://deviceanalyzer.cl.cam.ac.uk/collected.htm">best practices in privacy preservation</a> and will not identify you but it will help us hold manufacturers to account.</p>
 <p>If you have information about a vulnerability not listed on this site then you can <a href="submit">submit it</a>.</p>
 </div>
</div>



## Further information

We are collating all critical vulnerabilities in Android and storing this information in a [machine reable format (json)](spec) with references for each fact.
This can be used to compute the proportion of Android devices that are vulnerable to different vulerabilities, by using the [Device Analyzer](https://deviceanalyzer.cl.cam.ac.uk/) data.
Allows us to compare different manufacturers and network operators in terms of the time it takes them to supply updates to customers.
This work is being coordinated by [Daniel Thomas](submitters/drt24).

We are only tracking critical vulnerabilities which an app could exploit.
These are vulnerabilities that allow an app (malicious or compromised) to either gain root or gain privileges which can then be used to obtain root.

<div class="row" markdown="1">
<div class="three columns" markdown="1">

### [List of vulnerabilities](all)
* [by manufacturer](by/manufacturer)
* [by year](by/year)
* [by Android version](by/version)
* [by submitter](by/submitter)
* [by category](by/category)

</div>

<div class="nine columns" markdown="1">

### Published papers

 * ["Security metrics for the Android ecosystem" by Daniel R. Thomas, Alastair R. Beresford and Andrew Rice in ACM CCS Workshop on Security and Privacy in Smartphones and Mobile Devices (SPSM) 2015](https://www.cl.cam.ac.uk/~drt24/papers/spsm-scoring.pdf)
 * ["The lifetime of Android API vulnerabilities: case study on the JavaScript-to-Java interface" by Daniel R. Thomas, Alastair R. Beresford, Thomas Coudray, Tom Sutcliffe and Adrian Taylor in the Proceedings of the Security Protocols Workshop 2015](https://www.cl.cam.ac.uk/~drt24/papers/spw15-07-Thomas.pdf)

</div>
</div>

<h2 id="contact">Contact</h2>
<div class="row">
 <div class="five columns info">
   <a href="http://www.cam.ac.uk/"><img src="images/uc-cmyk.png" alt="University of Cambridge" /></a>
  <p>We can be reached at <a href="&#109;&#97;&#105;&#108;&#116;&#111;&#58;&#99;&#111;&#110;&#116;&#97;&#99;&#116;&#64;&#97;&#110;&#100;&#114;&#111;&#105;&#100;&#118;&#117;&#108;&#110;&#101;&#114;&#97;&#98;&#105;&#108;&#105;&#116;&#105;&#101;&#115;&#46;&#111;&#114;&#103;">&#99;&#111;&#110;&#116;&#97;&#99;&#116;&#64;&#97;&#110;&#100;&#114;&#111;&#105;&#100;&#118;&#117;&#108;&#110;&#101;&#114;&#97;&#98;&#105;&#108;&#105;&#116;&#105;&#101;&#115;&#46;&#111;&#114;&#103;</a>.<br/>
  This is a research project being run from the <a href="https://www.cl.cam.ac.uk/">Computer Laboratory</a> of the <a href="http://www.cam.ac.uk">University of Cambridge</a>.</p>
 </div>

 <div class="seven columns right-cols">
  <div class="row">
   <div class="four columns">
    <a href="https://www.cl.cam.ac.uk/~drt24/"><img src="images/people/drt24.jpg" alt="Picture of Daniel Thomas"/></a>
    <h5><a href="https://www.cl.cam.ac.uk/~drt24/">Daniel Thomas</a></h3>
    <p>Researcher</p>
   </div>

   <div class="four columns">
    <a href="https://www.cl.cam.ac.uk/~arb33/"><img src="images/people/arb33.jpg" alt="Picture of Alastair Beresford"/></a>
    <h5><a href="https://www.cl.cam.ac.uk/~arb33/">Alastair Beresford</a></h3>
    <p>Senior Lecturer</p>
   </div>

   <div class="four columns">
    <a href="https://www.cl.cam.ac.uk/~acr31/"><img src="images/people/acr31.jpg" alt="Picture of Andrew Rice"/></a>
    <h5><a href="https://www.cl.cam.ac.uk/~acr31/">Andrew Rice</a></h3>
    <p>Senior Lecturer</p>
   </div>
  </div> <!-- Nested Row End -->
 </div>
</div>
