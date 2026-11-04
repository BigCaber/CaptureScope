import os
here=os.path.dirname(os.path.abspath(__file__))
def r(f): return open(os.path.join(here,f)).read()
head=r('part_head.html'); body=r('part_body.html'); oui=r('oui.b64').strip()
js='\n'.join(r(f) for f in ['js_kb.js','js_parser.js','js_classify.js','js_model.js','js_render.js','js_pdf.js','js_app.js'])
out=head+body+'\n<script>\nconst OUI_B64="'+oui+'";\n</script>\n<script>\n'+js+'\n</script>\n</body>\n</html>\n'
outpath=os.path.join(here,'..','CaptureScope.html')
open(outpath,'w').write(out)
print('CaptureScope.html',round(os.path.getsize(outpath)/1024),'KB')
