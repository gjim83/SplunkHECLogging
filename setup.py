from distutils.core import setup

ver = '0.1.2'


def parse_requirements(filename):
    """
    Load requirements from a pip requirements file
    """
    with open(filename, 'r') as f:
        lineiter = (line.strip() for line in f.readlines())
    return [line for line in lineiter if line and not line.startswith("#")]


dl_url = (
    '<UPDTAE>/SplunkHECLogging/archive/{}.tar.gz'.
    format(ver)
)

setup(
    name='sheclog',
    packages=['sheclog'],
    version=ver,
    description=(
        "Send log messages to Splunk's HTTP Event Collector, powered by requests and logging"
    ),
    author='Guido Jimenez',
    author_email='guidojimenez@gmail.com',
    url='<UPDATE>/SplunkHECLogging',
    download_url=dl_url,
    keywords=['logging', 'splunk'],
    classifiers=[],
    install_requires=parse_requirements('requirements.txt')
)
