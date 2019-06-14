import sys
import os

# Add the ../SplunkHECLogging path to PYTHONPATH so that tests can import project modules
test_dir_path = os.path.dirname(
    os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__)))
)
project_dir = os.path.join(test_dir_path, '..')
sys.path.append(os.path.normpath(project_dir))
