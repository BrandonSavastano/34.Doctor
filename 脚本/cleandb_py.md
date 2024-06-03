```python
#!/usr/bin/env python3
import os

os.system('rm /home/web/blog/flaskblog/site.db')
os.system('cp /opt/clean/site.db /home/web/blog/flaskblog/site.db')
os.system('chown web:web /home/web/blog/flaskblog/site.db')

