#!/usr/bin/env python3
"""
Generate PDF documentation for NVC Fund Web4
"""
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.platypus.tableofcontents import SimpleIndex
import os
from documentation_content import *

class DocumentationGenerator:
    def __init__(self, output_file="NVC_Fund_Web4_Developer_Manual.pdf"):
        self.output_file = output_file
        self.styles = getSampleStyleSheet()
        self.story = []
        self.setup_styles()
        
    def setup_styles(self):
        """Setup custom styles for the document"""
        self.styles.add(ParagraphStyle(
            name='Heading1',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30
        ))
        self.styles.add(ParagraphStyle(
            name='Heading2',
            parent=self.styles['Heading2'],
            fontSize=18,
            spaceAfter=20
        ))
        self.styles.add(ParagraphStyle(
            name='Heading3',
            parent=self.styles['Heading3'],
            fontSize=14,
            spaceAfter=15
        ))
        self.styles.add(ParagraphStyle(
            name='Code',
            parent=self.styles['Code'],
            fontName='Courier',
            fontSize=10,
            leading=12
        ))
        
    def add_title(self):
        """Add document title"""
        self.story.append(Paragraph("NVC Fund Web4 Developer's Manual", self.styles['Heading1']))
        self.story.append(Spacer(1, 30))
        
    def add_toc(self):
        """Add table of contents"""
        self.story.append(Paragraph("Table of Contents", self.styles['Heading1']))
        self.story.append(Spacer(1, 20))
        
        # Add TOC entries
        toc_entries = [
            ("1. System Architecture", 1),
            ("2. Database Models", 1),
            ("3. Data Workflows", 1),
            ("4. Security Features", 1),
            ("5. Financial Operations", 1),
            ("6. Blockchain Integration", 1),
            ("7. API Integration", 1),
            ("8. Reporting and Analytics", 1),
            ("9. System Administration", 1),
            ("10. Compliance and Risk Management", 1),
        ]
        
        for title, level in toc_entries:
            self.story.append(Paragraph(title, self.styles[f'Heading{level}']))
            
    def add_section(self, title, content, level=1):
        """Add a section to the document"""
        self.story.append(Paragraph(title, self.styles[f'Heading{level}']))
        self.story.append(Spacer(1, 12))
        
        if isinstance(content, str):
            self.story.append(Paragraph(content, self.styles['Normal']))
        elif isinstance(content, list):
            for item in content:
                self.story.append(Paragraph(item, self.styles['Normal']))
                
    def add_code_block(self, code, language='python'):
        """Add a code block to the document"""
        self.story.append(Paragraph(f"```{language}", self.styles['Code']))
        self.story.append(Paragraph(code, self.styles['Code']))
        self.story.append(Paragraph("```", self.styles['Code']))
        self.story.append(Spacer(1, 12))
        
    def generate_pdf(self):
        """Generate the PDF document"""
        doc = SimpleDocTemplate(
            self.output_file,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Add content
        self.add_title()
        self.add_toc()
        self.story.append(PageBreak())
        
        # Add all sections
        self.add_section("1. System Architecture", SYSTEM_ARCHITECTURE)
        self.story.append(PageBreak())
        
        self.add_section("2. Database Models", DATABASE_MODELS)
        self.story.append(PageBreak())
        
        self.add_section("3. Data Workflows", DATA_WORKFLOWS)
        self.story.append(PageBreak())
        
        self.add_section("4. Security Features", SECURITY_FEATURES)
        self.story.append(PageBreak())
        
        self.add_section("5. Financial Operations", FINANCIAL_OPERATIONS)
        self.story.append(PageBreak())
        
        self.add_section("6. Blockchain Integration", BLOCKCHAIN_INTEGRATION)
        self.story.append(PageBreak())
        
        self.add_section("7. API Integration", API_INTEGRATION)
        self.story.append(PageBreak())
        
        self.add_section("8. Reporting and Analytics", REPORTING_ANALYTICS)
        self.story.append(PageBreak())
        
        self.add_section("9. System Administration", SYSTEM_ADMINISTRATION)
        self.story.append(PageBreak())
        
        self.add_section("10. Compliance and Risk Management", COMPLIANCE_RISK)
        
        # Build PDF
        doc.build(self.story)

def main():
    generator = DocumentationGenerator()
    generator.generate_pdf()
    print(f"Documentation generated: {generator.output_file}")

if __name__ == "__main__":
    main() 