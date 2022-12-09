from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()


setup(
    name='assess-mozilla-aws-security-infrastructure',
    version='1.0',
    packages=find_packages(include=["assess_mozilla_aws_security_infrastructure"]),
    url='https://github.com/mozilla/assess-mozilla-aws-security-infrastructure',
    license='MPL-2.0',
    author='Gene Wood',
    author_email='gene@mozilla.com',
    description="Tool to assess the state of security infrastructure in Mozilla's AWS accounts",
    long_description=readme,
    long_description_content_type='text/markdown',
    install_requires=['boto3', 'xdg'],
    entry_points={"console_scripts": ["assess-mozilla-aws-security-infrastructure=assess_mozilla_aws_security_infrastructure:main"]},
)
