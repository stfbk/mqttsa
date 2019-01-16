import fpdf
from fpdf import FPDF, HTMLMixin

class MyFPDF(FPDF, HTMLMixin):
    pass

pdf = MyFPDF()
font_size = 11
html = ''
check = False


# init the structure of the pdf and append the title in an HTML format
def init():
    global html
    global check
    pdf.add_page()
    html += '<H1 align="center">MQTTSA Report</H1>'
    check = True

# append a paragraph to the HTML 
def add_paragraph(title, msg=None):
    global html
    global check
    if check == False:
        init()
    if msg != None:
        html += '<h2 align="left">'+title+"</h2><font size="+str(font_size)+">"+msg+'</p><br>'
    else:
        html += '<h2 align="left">'+title+'</h2>'

# append a sub-paragraph to the HTML
def add_sub_paragraph(title, msg=None):
    global html
    if msg != None:
        html += '<h4 align="left">'+title+"</h4><font size="+str(font_size)+">"+msg+'</p><br>'
    else:
        html += '<h4 align="left">'+title+'</h4>'

# append into the existing paragraph of the HTML
def add_to_existing_paragraph(msg):
    global html
    html += "<font size="+str(font_size)+">"+msg+'</font><br>'

# generate the pdf using the HTML
def output_pdf():
    global html
    pdf.write_html(html)
    pdf.output("report.pdf")
