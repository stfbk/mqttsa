import fpdf
from fpdf import FPDF, HTMLMixin

# Create pdf report to show the results in a readable way
# The content of the pdf has to be written following the 
# HTML standard. It will be converted in pdf at the end, 
# using output_pdf()

class MyFPDF(FPDF, HTMLMixin):
    pass

# parameters for the pdf
pdf = MyFPDF()
font_size = 11
html = ''
check = False


# initialize the structure of the pdf and append the title of the report in an HTML format
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
        html += '<h2 align="left">'+title+"</h2><font size="+str(font_size)+">"+msg+'</font><br>'
    else:
        html += '<h2 align="left">'+title+'</h2>'
       
# Create summary table
def add_summary_table(title, IP, Port, Listening, Msg, Interface, MD, F_DoS, FSize_DoS, S_DoS, DoS_data, Brute, outdated, implements_TLS, disclosure, weak_ac, no_pass, cred_sniffed_or_bruteforced, client_key):
    global html
    Rating = 0
    
    # If it managed to connect (excluding when provided with X.509 certificates)
    if (weak_ac):
        Rating += 8
        if(client_key):
            Rating -= 8
        # But no password
        if(no_pass):
            Rating += 2
        # Or using hijacked credentials
        if(cred_sniffed_or_bruteforced):
            Rating += 4

    if(DoS_data):
        if(DoS_data[0]==DoS_data[1]):
            queue_string = f"Yes ({DoS_data[0]}/{DoS_data[1]} messages)"
            Rating -= 1
        elif(DoS_data[1] == None):
            queue_string = "Skipped"
        else:
            queue_string = f"No ({DoS_data[0]}/{DoS_data[1]} messages)"
            Rating += 1
        
        if(DoS_data[2]==DoS_data[3]):
            payload_string = f"Yes (up to {DoS_data[2]}MB message)"
            Rating -= 2
        elif(DoS_data[3] == None):
            payload_string = "Skipped"
        else:
            payload_string = f"No (max {DoS_data[2]}MB message)"
            Rating += 2
        
        if(DoS_data[4]==DoS_data[5]):
            connection_string = f"Yes ({DoS_data[4]} conn. accepted)"
            Rating -= 1
        elif(DoS_data[5] == None):
            connection_string = "Skipped"
        else:
            connection_string = f"No (max {DoS_data[4]} conn. accepted)"
            Rating += 1
    else:
        queue_string = "Skipped"
        payload_string = queue_string
        connection_string = queue_string
        
    # E.g., when providing only CA certificate
    if(implements_TLS):
        Rating -= 4
    # Implies no ACL
    if(disclosure):
        Rating += 2
        
    if (Rating <=0):
        Rating = "Null or not evaluable"
    elif (Rating <3):
        Rating = "LOW"
    elif (Rating <7):
        Rating = "MEDIUM"
    else:
        Rating = "HIGH"
    
    html += '<h4 align="left">'+title+'</h4>'\
        '<table width="100%">'\
        '<thead>'\
        '    <tr width="100%">'\
        '      <th><center>Test configuration</center></th>'\
        '      <th> </th>'\
        '      <th><center>Vulnerabilities</center></th>'\
        '      <th> </th>'\
        '    </tr>'\
        '</thead>'\
        '<tbody>'\
        '    <tr width="100%">'\
        '      <td>Broker host and port</td>'\
        '      <td>'+ IP +':'+ Port +'</td>'\
        '      <td>Outdated Broker</td>'\
        '      <td><center>' + outdated + '</center></td>'\
        '    </tr>'\
        '    <tr width="100%">'\
        '        <td>Listening time</td>'\
        '        <td>' + Listening + ' seconds </td>'\
        '        <td>Use of TLS</td>'\
        '        <td><center>'+ str(implements_TLS) +'*</center></td>'\
        '    </tr>'\
        '    <tr width="100%">'\
        '        <td>Message to send</td>'\
        '        <td>' + Msg + '</td>'\
        '        <td>Information Disclosure</td>'\
        '        <td><center>'+ disclosure +'</center></td>'\
        '    </tr>'\
        '    <tr width="100%">'\
        '        <td>Sniffing interface</td>'\
        '        <td>' + Interface + '</td>'\
        '        <td>Accessible service</td>'\
        '        <td><center>'+ str(weak_ac) +'</center></td>'\
        '    </tr>'\
        '    <tr width="100%">'\
        '        <td>Data/Msg tampering</td>'\
        '        <td>' + MD + '</td>'\
        '        <td>or weak Access Control</td>'\
        '        <td></td>'\
        '    </tr>'\
        '    <tr width="100%">'\
        '        <td>Brute-forcing</td>'\
        '        <td>' + Brute + '</td>'\
        '        <td>Unlimited** payload</td>'\
        '        <td>' + payload_string + '</td>'\
        '    </tr>'\
        '    <tr width="100%">'\
        '        <td>Flooding DoS conn.</td>'\
        '        <td>' + F_DoS + '</td>'\
        '        <td>Unlimited** connections</td>'\
        '        <td>' + connection_string + '</td>'\
        '    </tr>'\
        '    <tr width="100%">'\
        '        <td>- Payload size</td>'\
        '        <td>' + FSize_DoS + '</td><'\
        '        <td>Unlimited** msg queues</td>'\
        '        <td>' + queue_string + '</td>'\
        '    </tr>'\
        '    <tr width="100%">'\
        '        <td>Slow DoS conn.</td>'\
        '        <td>' + S_DoS + '</td>'\
        '        <td>Overall risk</td>'\
        '        <td><center>'+ Rating +'</center></td>'\
        '    </tr>'\
        '</tbody>'\
        '</table>' +"<font size="+str(font_size)+">*: False if not providing X.509 certificates or according to the broker implementation (e.g., Mosquitto). Verify with TLS Assistant (<a href=\"https://github.com/stfbk/tlsassistant\">https://github.com/stfbk/tlsassistant</a>).<br>**: With respect to provided parameters.</font><br><br>"

# append a sub-paragraph to the HTML
def add_sub_paragraph(title, msg=None):
    global html
    if msg != None:
        html += '<h4 align="left">'+title+"</h4><font size="+str(font_size)+">"+msg+'</font><br>'
    else:
        html += '<h4 align="left">'+title+'</h4>'

# append to an existing paragraph of the HTML
def add_to_existing_paragraph(msg):
    global html
    html += "<font size="+str(font_size)+">"+msg+'</font><br>'

# generate the pdf using the HTML
def output_pdf(fingerprint):
    global html
    
    html = html.replace("Replace_up_to_date", fingerprint)
    
    pdf.write_html(html.encode('utf-8').decode('latin-1'))
    pdf.output("report.pdf")
