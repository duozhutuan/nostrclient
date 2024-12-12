
import os
from setuptools import setup

about = {}
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "src", "__version__.py"), "r") as f:
    exec(f.read(), about)

setup(version=about['__version__'])

