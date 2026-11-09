"""
Pure Python PDF Document Generator for DualShield Project Report.
Zero external dependencies required. Produces valid, standard PDF 1.4.
"""

import os
import re

class SimplePDFBuilder:
    def __init__(self, filename="PROJECT_REPORT.pdf"):
        self.filename = filename
        self.pages = []
        self.current_page_ops = []
        self.width = 612.0   # 8.5 inches in points
        self.height = 792.0  # 11 inches in points
        self.margin_left = 50.0
        self.margin_right = 562.0
        self.content_width = self.margin_right - self.margin_left # 512 pt
        self.margin_top = 740.0
        self.margin_bottom = 50.0
        self.y = self.margin_top
        self.page_number = 0

    def start_page(self):
        self.page_number += 1
        self.current_page_ops = []
        self.y = self.margin_top
        
        # Header banner (pages > 1)
        if self.page_number > 1:
            # Header line
            self.draw_rect(self.margin_left, 755, self.content_width, 0.75, fill=False, stroke=True, stroke_color=(0.8, 0.83, 0.88))
            # Header text
            self.add_text(self.margin_left, 760, "DUALSHIELD EMAIL GUARD: TECHNICAL SPECIFICATION & PROJECT REPORT", font="F1", size=7.5, color=(0.4, 0.45, 0.5))
            self.add_text(self.margin_right - 45, 760, f"Page {self.page_number}", font="F1", size=7.5, color=(0.4, 0.45, 0.5))

        # Footer
        self.draw_rect(self.margin_left, 38, self.content_width, 0.75, fill=False, stroke=True, stroke_color=(0.85, 0.88, 0.92))
        self.add_text(self.margin_left, 26, "Confidential - For Academic and Technical Evaluation Only", font="F1", size=7.5, color=(0.5, 0.55, 0.6))
        self.add_text(self.margin_right - 65, 26, "Google Antigravity", font="F2", size=7.5, color=(0.1, 0.5, 0.4))

    def check_space(self, needed_pts):
        if self.y - needed_pts < self.margin_bottom:
            self.pages.append(self.current_page_ops)
            self.start_page()

    def add_op(self, op_str):
        self.current_page_ops.append(op_str)

    def draw_rect(self, x, y, w, h, fill=True, stroke=False, fill_color=(0.95, 0.96, 0.98), stroke_color=(0.8, 0.85, 0.9)):
        r, g, b = fill_color
        sr, sg, sb = stroke_color
        ops = []
        if fill:
            ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        if stroke:
            ops.append(f"{sr:.3f} {sg:.3f} {sb:.3f} RG")
        ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        if fill and stroke:
            ops.append("B")
        elif fill:
            ops.append("f")
        else:
            ops.append("S")
        self.add_op(" ".join(ops))

    def sanitize_text(self, text):
        # Replace common unicode chars with ASCII or WinAnsi
        text = text.replace('\u2022', '-').replace('\u2014', '--').replace('\u2013', '-')
        text = text.replace('\u2018', "'").replace('\u2019', "'").replace('\u201c', '"').replace('\u201d', '"')
        # Filter to ascii only
        text = "".join([c if ord(c) < 128 else '' for c in text])
        return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

    def add_text(self, x, y, text, font="F1", size=9.5, color=(0.15, 0.18, 0.22)):
        r, g, b = color
        safe_str = self.sanitize_text(text)
        op = f"BT /{font} {size} Tf {r:.3f} {g:.3f} {b:.3f} rg {x:.2f} {y:.2f} Td ({safe_str}) Tj ET"
        self.add_op(op)

    def add_title_block(self, title, subtitle, metadata_items):
        self.check_space(140)
        # Background box
        self.draw_rect(self.margin_left, self.y - 120, self.content_width, 120, fill=True, stroke=True, 
                       fill_color=(0.96, 0.98, 0.99), stroke_color=(0.1, 0.6, 0.45))
        
        # Decorative left bar
        self.draw_rect(self.margin_left, self.y - 120, 6, 120, fill=True, stroke=False, fill_color=(0.06, 0.60, 0.45))

        # Title text
        self.add_text(self.margin_left + 18, self.y - 28, title, font="F2", size=16, color=(0.05, 0.2, 0.35))
        # Subtitle
        self.add_text(self.margin_left + 18, self.y - 48, subtitle, font="F2", size=10, color=(0.08, 0.5, 0.4))

        # Metadata grid
        curr_y = self.y - 72
        for key, val in metadata_items:
            self.add_text(self.margin_left + 18, curr_y, f"{key}:", font="F2", size=8.5, color=(0.25, 0.3, 0.38))
            self.add_text(self.margin_left + 115, curr_y, val, font="F1", size=8.5, color=(0.15, 0.18, 0.22))
            curr_y -= 14

        self.y -= 135

    def add_heading1(self, text):
        self.check_space(45)
        self.y -= 12
        # Underline bar
        self.draw_rect(self.margin_left, self.y - 4, self.content_width, 1.5, fill=True, stroke=False, fill_color=(0.06, 0.55, 0.42))
        self.add_text(self.margin_left, self.y, text, font="F2", size=12.5, color=(0.05, 0.22, 0.36))
        self.y -= 18

    def add_heading2(self, text):
        self.check_space(32)
        self.y -= 8
        self.add_text(self.margin_left, self.y, text, font="F2", size=10.5, color=(0.1, 0.35, 0.45))
        self.y -= 15

    def add_paragraph(self, text, indent=0, size=9.0, leading=12.5, color=(0.15, 0.18, 0.22)):
        # Word wrap based on approx char width (approx 4.8 pt per char at 9pt)
        max_chars = int((self.content_width - indent) / 4.7)
        words = text.split()
        lines = []
        current_line = []
        current_len = 0

        for w in words:
            if current_len + len(w) + 1 > max_chars:
                lines.append(" ".join(current_line))
                current_line = [w]
                current_len = len(w)
            else:
                current_line.append(w)
                current_len += len(w) + 1
        if current_line:
            lines.append(" ".join(current_line))

        for line in lines:
            self.check_space(leading + 2)
            self.add_text(self.margin_left + indent, self.y, line, font="F1", size=size, color=color)
            self.y -= leading

        self.y -= 4

    def add_bullet_point(self, title, body):
        self.check_space(24)
        # Draw clean decorative colored bullet dot
        self.draw_rect(self.margin_left + 8, self.y - 8, 3.5, 3.5, fill=True, stroke=False, fill_color=(0.06, 0.55, 0.42))
        
        prefix = f"{title}: " if title else ""
        full_text = prefix + body
        
        max_chars = int((self.content_width - 24) / 4.7)
        words = full_text.split()
        lines = []
        current_line = []
        current_len = 0

        for w in words:
            if current_len + len(w) + 1 > max_chars:
                lines.append(" ".join(current_line))
                current_line = [w]
                current_len = len(w)
            else:
                current_line.append(w)
                current_len += len(w) + 1
        if current_line:
            lines.append(" ".join(current_line))

        for i, line in enumerate(lines):
            self.check_space(13)
            if i == 0 and title:
                # First line bold title
                self.add_text(self.margin_left + 22, self.y, title + ": ", font="F2", size=8.8, color=(0.1, 0.2, 0.3))
                offset = len(title + ": ") * 4.8
                rem_line = line[len(title + ": "):]
                self.add_text(self.margin_left + 22 + offset, self.y, rem_line, font="F1", size=8.8, color=(0.18, 0.2, 0.25))
            else:
                self.add_text(self.margin_left + 22, self.y, line, font="F1", size=8.8, color=(0.18, 0.2, 0.25))
            self.y -= 12.5

        self.y -= 2

    def add_callout_box(self, alert_title, message):
        self.check_space(55)
        box_height = 42
        self.draw_rect(self.margin_left, self.y - box_height, self.content_width, box_height, fill=True, stroke=True,
                       fill_color=(0.99, 0.98, 0.94), stroke_color=(0.95, 0.75, 0.25))
        self.draw_rect(self.margin_left, self.y - box_height, 4, box_height, fill=True, stroke=False, fill_color=(0.9, 0.6, 0.1))
        
        self.add_text(self.margin_left + 14, self.y - 14, alert_title, font="F2", size=9, color=(0.6, 0.35, 0.05))
        self.add_text(self.margin_left + 14, self.y - 28, message, font="F1", size=8.5, color=(0.35, 0.25, 0.1))
        self.y -= (box_height + 10)

    def add_table(self, headers, rows, col_widths):
        total_w = sum(col_widths)
        scale = self.content_width / total_w
        widths = [w * scale for w in col_widths]
        row_h = 17

        self.check_space(row_h * (len(rows) + 1) + 10)

        # Header row
        self.draw_rect(self.margin_left, self.y - row_h, self.content_width, row_h, fill=True, stroke=True,
                       fill_color=(0.06, 0.52, 0.40), stroke_color=(0.04, 0.40, 0.30))
        cur_x = self.margin_left
        for i, h in enumerate(headers):
            self.add_text(cur_x + 5, self.y - 12, h, font="F2", size=8.2, color=(1.0, 1.0, 1.0))
            cur_x += widths[i]

        self.y -= row_h

        # Data rows
        for r_idx, row in enumerate(rows):
            self.check_space(row_h)
            fill_col = (0.98, 0.99, 1.0) if r_idx % 2 == 0 else (1.0, 1.0, 1.0)
            self.draw_rect(self.margin_left, self.y - row_h, self.content_width, row_h, fill=True, stroke=True,
                           fill_color=fill_col, stroke_color=(0.88, 0.90, 0.94))
            
            cur_x = self.margin_left
            for i, cell in enumerate(row):
                cell_str = str(cell)
                # Color code status
                text_col = (0.15, 0.18, 0.22)
                f_name = "F1"
                if cell_str in ["BLOCKED", "PASS"]:
                    text_col = (0.75, 0.1, 0.1) if cell_str == "BLOCKED" else (0.05, 0.55, 0.3)
                    f_name = "F2"
                elif cell_str == "NOTIFIED":
                    text_col = (0.75, 0.45, 0.05)
                    f_name = "F2"
                elif cell_str == "ALLOWED":
                    text_col = (0.05, 0.55, 0.3)
                    f_name = "F2"

                self.add_text(cur_x + 5, self.y - 12, cell_str[:28], font=f_name, size=8.0, color=text_col)
                cur_x += widths[i]
            
            self.y -= row_h

        self.y -= 10

    def compile_pdf(self):
        # Save last page if ops exist
        if self.current_page_ops:
            self.pages.append(self.current_page_ops)

        # PDF Object collection
        objects = []
        
        # Obj 1: Catalog
        # Obj 2: Outlines
        # Obj 3: Pages
        # Obj 4: Font F1 (Helvetica)
        # Obj 5: Font F2 (Helvetica-Bold)
        # Obj 6: Font F3 (Courier)
        # Next objects: Page objects and Content stream objects
        
        num_pages = len(self.pages)
        page_obj_ids = [7 + i * 2 for i in range(num_pages)]
        content_obj_ids = [8 + i * 2 for i in range(num_pages)]

        # 1. Catalog
        objects.append("<< /Type /Catalog /Pages 3 0 R >>")
        # 2. Outlines
        objects.append("<< /Type /Outlines /Count 0 >>")
        # 3. Pages
        kids_str = " ".join([f"{pid} 0 R" for pid in page_obj_ids])
        objects.append(f"<< /Type /Pages /Kids [{kids_str}] /Count {num_pages} >>")
        # 4. Font F1
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        # 5. Font F2
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        # 6. Font F3
        objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")

        # Page and Content objects
        for i in range(num_pages):
            pid = page_obj_ids[i]
            cid = content_obj_ids[i]
            page_obj = f"<< /Type /Page /Parent 3 0 R /MediaBox [0 0 {self.width:.1f} {self.height:.1f}] /Contents {cid} 0 R /Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> >> >>"
            objects.append(page_obj)

            # Content stream
            stream_body = "\n".join(self.pages[i])
            stream_bytes = stream_body.encode('latin1')
            stream_obj = f"<< /Length {len(stream_bytes)} >>\nstream\n{stream_body}\nendstream"
            objects.append(stream_obj)

        # Build final binary
        pdf_lines = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
        xref_offsets = []

        for idx, obj_content in enumerate(objects, 1):
            offset = sum(len(line) for line in pdf_lines)
            xref_offsets.append(offset)
            if isinstance(obj_content, str):
                pdf_lines.append(f"{idx} 0 obj\n{obj_content}\nendobj\n".encode('latin1'))
            else:
                pdf_lines.append(f"{idx} 0 obj\n".encode('latin1') + obj_content + b"\nendobj\n")

        # XREF Table
        xref_start = sum(len(line) for line in pdf_lines)
        pdf_lines.append(f"xref\n0 {len(objects) + 1}\n".encode('latin1'))
        pdf_lines.append(b"0000000000 65535 f \n")
        for off in xref_offsets:
            pdf_lines.append(f"{off:010d} 00000 n \n".encode('latin1'))

        # Trailer
        trailer_str = f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n"
        pdf_lines.append(trailer_str.encode('latin1'))

        with open(self.filename, 'wb') as f:
            for l in pdf_lines:
                f.write(l)

        print(f"Successfully compiled PDF: {self.filename} ({len(self.pages)} pages)")
