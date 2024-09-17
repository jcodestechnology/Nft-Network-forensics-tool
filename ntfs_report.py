from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, PageBreak, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from ntfs_data import create_connection, get_pcap_analysis_for_case

def add_page_number(canvas, doc):
    page_num = canvas.getPageNumber()
    text = f"Page {page_num}"
    canvas.drawRightString(200 * mm, 20 * mm, text)

def generate_pdf_report(case_details, pcap_files):
    if not case_details or len(case_details) < 3:
        print("Error: Insufficient case details or case not found.")
        return
    
    case_name = case_details[0]
    org_name = case_details[1]
    investigator_name = case_details[2]
    date = case_details[3]
    
    pdf_file = f"{case_name}_report.pdf"
    doc = SimpleDocTemplate(pdf_file, pagesize=A4)
    elements = []
    
    styles = getSampleStyleSheet()
    
    # Define custom styles
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontSize=24,
        leading=28,
        alignment=TA_CENTER,
        spaceAfter=20 
    )
    subtitle_style = ParagraphStyle(
        'Subtitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        spaceAfter=20
    )
    left_aligned_subtitle_style = ParagraphStyle(
    'LeftAlignedSubtitle',
    parent=styles['Normal'],
    fontSize=15,
    leading=17,
    alignment=TA_LEFT,
    spaceAfter=20
)
    normal_centered = ParagraphStyle(
        'NormalCentered',
        parent=styles['Normal'],
        fontSize=12,
        leading=14,
        alignment=TA_CENTER,
        spaceAfter=10
    )
    normal_left = ParagraphStyle(
        'NormalLeft',
        parent=styles['Normal'],
        fontSize=11,
        leading=14,
        alignment=TA_LEFT,
        spaceAfter=10
    )
    heading_left = ParagraphStyle(
        'HeadingLeft',
        parent=styles['Heading2'],
        alignment=TA_LEFT,
        spaceAfter=10
    )
    findings_title_style = ParagraphStyle(
        'FindingsTitle',
        parent=styles['Heading1'],
        fontSize=18,
        leading=22,
        alignment=TA_CENTER,
        spaceBefore=20,
        spaceAfter=20
    )

    # Cover Page

    page_width, page_height = A4

    elements.append(Spacer(1, page_height / 3))
    elements.append(Paragraph("NETWORK FORENSIC TOOL", title_style))
    elements.append(Paragraph("Report For Web Traffic Analysis", subtitle_style))
    elements.append(Spacer(1, page_height / 3))

    elements.append(PageBreak())

    # elements.append(Spacer(1, 5))
    # elements.append(Paragraph("Table of Content", subtitle_style))

    # elements.append(PageBreak())

    # Summary Page
    elements.append(Spacer(1, 5))
    elements.append(Paragraph("Summary", subtitle_style))

    elements.append(Spacer(1, 7))  # Adjust spacing as needed

    # Explanation about DoS and DDoS attacks
    elements.append(Paragraph("DoS/DDoS Attack", left_aligned_subtitle_style))
    elements.append(Paragraph("A denial-of-service (DoS) attack floods a server with traffic, making a website or resource unavailable.", normal_left))

    elements.append(Spacer(1, 7))

    elements.append(Paragraph("A distributed denial-of-service (DDoS) attack is a malicious attempt to disrupt the normal traffic of a targeted server, service, or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic.", normal_left))
    elements.append(Paragraph("DDoS attacks achieve effectiveness by utilizing multiple compromised computer systems as sources of attack traffic. Exploited machines can include computers and other networked resources such as IoT devices.", normal_left))

    elements.append(Spacer(1, 7))

    elements.append(Paragraph("How to identify a DDoS attack", left_aligned_subtitle_style))
    elements.append(Paragraph("The most obvious symptom of a DDoS attack is a site or service suddenly becoming slow or unavailable. But since a number of causes — such as a legitimate spike in traffic — can create similar performance issues, further investigation is usually required. Traffic analytics tools can help you spot some of these telltale signs of a DDoS attack:", normal_left))

    # Bullet points 
    bullet_points = [
        "Suspicious amounts of traffic originating from a single IP address or IP range",
        "A flood of traffic from users who share a single behavioral profile, such as device type, geolocation, or web browser version",
        "An unexplained surge in requests to a single page or endpoint",
        "Odd traffic patterns such as spikes at odd hours of the day or patterns that appear to be unnatural (e.g., a spike every 10 minutes)"
    ]

    for point in bullet_points:
        elements.append(Paragraph(f"• {point}", normal_left))

    elements.append(Paragraph("There are other, more specific signs of a DDoS attack that can vary depending on the type of attack.", normal_left))

    elements.append(PageBreak())  

    elements.append(Spacer(1, 5))
    elements.append(Paragraph("Types of DoS Attacks and DDoS Attacks", subtitle_style))

    elements.append(Spacer(1, 17)) 

    # Teardrop Attack
    elements.append(Paragraph("Teardrop attack", left_aligned_subtitle_style))
    elements.append(Paragraph("A teardrop attack is a DoS attack that sends countless Internet Protocol (IP) data fragments to a network. When the network tries to recompile the fragments into their original packets, it is unable to.", normal_left))
    elements.append(Paragraph("For example, the attacker may take very large data packets and break them down into multiple fragments for the targeted system to reassemble. However, the attacker changes how the packet is disassembled to confuse the targeted system, which is then unable to reassemble the fragments into the original packets.", normal_left))

    elements.append(Spacer(1, 7))

    # Flooding Attack
    elements.append(Paragraph("Flooding attack", left_aligned_subtitle_style))
    elements.append(Paragraph("A flooding attack is a DoS attack that sends multiple connection requests to a server but then does not respond to complete the handshake.", normal_left))
    elements.append(Paragraph("For example, the attacker may send various requests to connect as a client, but when the server tries to communicate back to verify the connection, the attacker refuses to respond. After repeating the process countless times, the server becomes so inundated with pending requests that real clients cannot connect, and the server becomes 'busy' or even crashes.", normal_left))

    elements.append(Spacer(1, 7))

    # Protocol Attack
    elements.append(Paragraph("Protocol attack", left_aligned_subtitle_style))
    elements.append(Paragraph("A protocol attack is a type of DDoS attack that exploits weaknesses in Layers 3 and 4 of the OSI model. For example, the attacker may exploit the TCP connection sequence, sending requests but either not answering as expected or responding with another request using a spoofed source IP address. Unanswered requests use up the resources of the network until it becomes unavailable.", normal_left))

    elements.append(Spacer(1, 7))

    # Application-based Attack
    elements.append(Paragraph("Application-based attack", left_aligned_subtitle_style))
    elements.append(Paragraph("An application-based attack is a type of DDoS attack that targets Layer 7 of the OSI model. An example is a Slowloris attack, in which the attacker sends partial Hypertext Transfer Protocol (HTTP) requests but does not complete them. HTTP headers are periodically sent for each request, resulting in the network resources becoming tied up.", normal_left))
    elements.append(Paragraph("The attacker continues the onslaught until no new connections can be made by the server. This type of attack is very difficult to detect because rather than sending corrupted packets, it sends partial ones, and it uses little to no bandwidth.", normal_left))

    elements.append(PageBreak())  # Move to the next page

    # Introduction Page
    elements.append(Spacer(1, 5))
    elements.append(Paragraph("Introduction", subtitle_style))

    elements.append(Spacer(1, 7))  # Adjust spacing as needed

    # Detailed Explanation of the Tool
    elements.append(Paragraph("Network Forensic Tool for DDoS Detection", left_aligned_subtitle_style))

    elements.append(Paragraph("""
    This is a report on network forensics focusing on web-based traffic, specifically targeting the detection of Denial-of-Service (DoS) and Distributed Denial-of-Service (DDoS) attacks. The analysis presented in this report is conducted using a specialized network forensic tool designed to capture, import, and analyze network packets to identify malicious activities aimed at disrupting services.
    """, normal_left))

    elements.append(Paragraph("""
    The network forensic tool enables investigators to capture network packets in real-time, marking the status of the captured file as "captured". Additionally, it allows for the importation of pre-existing packet capture (PCAP) files, with the status being marked as "imported". Each captured or imported file is saved with a specific hash value to ensure data integrity and authenticity.
    """, normal_left))

    elements.append(Paragraph("""
    Upon obtaining the PCAP file, whether captured or imported, the tool performs a thorough analysis of the network traffic within the file. The analysis aims to identify patterns and anomalies that are characteristic of DoS and DDoS attacks. This includes examining various metrics such as packet counts, IP addresses, protocol usage, and traffic behavior over time.
    """, normal_left))

    elements.append(Paragraph("""
    After analyzing the traffic, the tool provides a detailed output indicating whether a DoS or DDoS attack pattern was observed. If an attack pattern is detected, the tool identifies the specific type of attack, such as SYN flood, UDP flood, or application-layer attacks like Slowloris. The findings are compiled into a comprehensive report, detailing the nature of the detected attack, the methodologies used for detection, and relevant statistics and insights.
    """, normal_left))

    elements.append(PageBreak())


    # Anaysis Details
    elements.append(Paragraph("Analysis Result", subtitle_style))
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("Case Details:", heading_left))
    case_info = f"""
    <b>Case Name:</b> {case_name}<br/>
    <b>Organization Name:</b> {org_name}<br/>
    <b>Investigator Name:</b> {investigator_name}<br/>
    <b>Date:</b> {date}<br/><br/>
    """
    elements.append(Paragraph(case_info, normal_left))

    

    # PCAP Files Page
    elements.append(Paragraph("PCAP Files:", styles['Heading1']))
    
    pcap_table_data = [["Pcap File", "Date", "Status"]]
    for file in pcap_files:
        pcap_table_data.append([file[0], file[1], file[2]])
    
    pcap_table = Table(pcap_table_data, colWidths=[300, 100, 100])
    pcap_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(pcap_table)
    elements.append(PageBreak())

    # PCAP Analysis Page
    elements.append(Paragraph("PCAP Analysis Report:", styles['Heading1']))

    connection = create_connection("ntfs.db")
    pcap_analysis = get_pcap_analysis_for_case(connection, case_name)

    if not pcap_analysis:
        elements.append(Paragraph("No analysis data found.", styles['Normal']))

    else:
        for analysis in pcap_analysis:
            analysis_info = f"""
            <b>PCAP File:</b> {analysis[3]}<br/>
            <b>Total Packets:</b> {analysis[4]}<br/>
            <b>TCP Count:</b> {analysis[6]}<br/>
            <b>UDP Count:</b> {analysis[7]}<br/>
            <b>HTTP Count:</b> {analysis[8]}<br/>
            <b>SYN Count:</b> {analysis[9]}<br/>
            <b>SYN-ACK Count:</b> {analysis[10]}<br/>
            <b>ACK Count:</b> {analysis[11]}<br/>
            <b>SYN without ACK Count:</b> {analysis[12]}<br/>
            <b>SYN-ACK Ratio:</b> {analysis[13]}<br/>
            <b>SYN-ACK Ratio Result:</b> {analysis[14]}<br/>
            <b>Proportionality Ratio Result:</b> {analysis[15]}<br/>
            <b>File Hash:</b> {analysis[16]}<br/>
            <b>Analysis Date:</b> {analysis[17]}<br/><br/>
            """
            elements.append(Paragraph(analysis_info, styles['Normal']))

            # Table for the list of IP addresses
            ip_addresses = eval (analysis[5])
            ip_data = [["IP", "Count"]] 

            for ip, count in ip_addresses:
                ip_data.append([ip, count])

            ip_table = Table(ip_data, colWidths=[200, 100])
            ip_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            elements.append(ip_table)
            elements.append(PageBreak())
            elements.append(Spacer(1, 12))

            


    # Add the page numbers
    doc.build(elements, onLaterPages=add_page_number)

    print(f"Report generated: {pdf_file}")

if __name__ == "__main__":
    # You can add test code or leave this block empty if not needed
    pass
