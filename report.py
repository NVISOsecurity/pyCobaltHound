import os
import time
# HTML templates

top = """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
.collapsible {
  background-color: #777;
  color: white;
  cursor: pointer;
  padding: 18px;
  width: 100%;
  border: none;
  text-align: left;
  outline: none;
  font-size: 15px;
}

.active, .collapsible:hover {
  background-color: #555;
}

.collapsible:after {
  content: '+';
  color: white;
  font-weight: bold;
  float: right;
  margin-left: 5px;
}

.active:after {
  content: "-";
}

.content {
  padding: 0 18px;
  max-height: 0;
  overflow: hidden;
  transition: max-height 0.2s ease-out;
  background-color: #f1f1f1;
}
</style>
</head>
<body>"""

title = """<h2>pyCobaltHound report - """

button = """<button type="button" class="collapsible">{query_name}</button>
<div class="content">
<ul>"""

bot = """<script>
var coll = document.getElementsByClassName("collapsible");
var i;

for (i = 0; i < coll.length; i++) {
  coll[i].addEventListener("click", function() {
    this.classList.toggle("active");
    var content = this.nextElementSibling;
    if (content.style.maxHeight){
      content.style.maxHeight = null;
    } else {
      content.style.maxHeight = content.scrollHeight + "px";
    } 
  });
}
</script>

</body>
</html>"""

def parse_results(user_results, computer_results):
  html = '\n'
  if all(len(result['result']) == 0 for result in user_results) == False:
    html = html + "<h3>User results</h3>" + '\n'
    for result in user_results:
      if len(result['result']) != 0:
        html = html + button.format(query_name=(result['report'].format(number=len(result['result'])))) + '\n'
        for object in result['result']:
          html = html + '<li>' + object + '</li>' + '\n'
        html = html + '</ul>' + '\n' + '</div>' + '\n'

  if all(len(result['result']) == 0 for result in computer_results) == False:
    html = html + "<h3>Computer results</h3>" + '\n'
    for result in computer_results:
      if len(result['result']) != 0:  
        html = html + button.format(query_name=(result['report'].format(number=len(result['result'])))) + '\n'
        for object in result['result']:
          html = html + '<li>' + object + '</li>' + '\n'
        html = html + '</ul>' + '\n' + '</div>' + '\n'
  return html

def generate_html_report(user_results, computer_results):
  report = ''
  if all(len(result['result']) == 0 for result in user_results) == False or all(len(result['result']) == 0 for result in computer_results) == False:
    inner_html = parse_results(user_results, computer_results)
    report = top + title + time.strftime("%Y-%m-%d %H:%M:%S") + '</h3>' + inner_html + bot
  return report

def generate_report(user_results, computer_results):
  reportdir = os.path.realpath(os.path.dirname(__file__)) + '/reports'
  if os.path.isdir(reportdir) == False:
    os.makedirs(reportdir)
  
  reportdest = reportdir + "/pycobalthound-report-" + time.strftime("%Y%m%d-%H%M%S") + ".html"
  report = generate_html_report(user_results, computer_results)
  f = open(reportdest, "w")
  f.write(report)
  f.close()
  return reportdest

  

  