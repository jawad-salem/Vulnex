from setuptools import setup, find_packages

with open('README.md', encoding='utf-8') as f:
    long_description = f.read()

with open('requirements.txt', encoding='utf-8') as f:
    requirements = [
        line.strip() for line in f
        if line.strip() and not line.startswith('#')
    ]

setup(
    name='vulnex',
    version='1.0.0',
    description='A penetration testing workflow platform built with Django',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Jawad Salem',
    url='https://github.com/jawad-salem/Vulnex',
    license='MIT',
    packages=find_packages(exclude=['*.migrations', '*.migrations.*']),
    include_package_data=True,
    python_requires='>=3.11',
    install_requires=requirements,
    entry_points={
        'console_scripts': [
            'vulnex=manage:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Framework :: Django :: 4.2',
        'Framework :: Django :: 5.0',
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
    ],
)
