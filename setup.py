
import os
from setuptools import setup,find_packages

about = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "NOPY", "__version__.py"), "r") as f:
    exec(f.read(), about)

setup(name="NOPY",
      version=about['__version__'],
      packages=find_packages(),)

