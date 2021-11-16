from distutils.core import setup
setup(
  name = 'openssl_ocsp_responder',
  packages = ['openssl_ocsp_responder'],
  version = '0.3',
  license='MIT',
  description = 'Simple wrapper for OpenSSL OCSP server',
  author = 'Eyal Brami',
  author_email = 'eyal.brami@redis.com',
  url = 'https://github.com/eyalbrami1/openssl_ocsp_responder',
  download_url = 'https://github.com/eyalbrami1/openssl_ocsp_responder/archive/refs/tags/v0.3.tar.gz',
  keywords = ['ocsp', 'ssl', 'openssl'],
  install_requires=[            # I get to this in a second
          'validators',
          'beautifulsoup4',
      ],
  classifiers=[
    'Development Status :: 3 - Alpha',      # Chose either "3 - Alpha", "4 - Beta" or "5 - Production/Stable" as the current state of your package
    'Intended Audience :: Developers',      # Define that your audience are developers
    'Topic :: Software Development :: Build Tools',
    'License :: OSI Approved :: MIT License',   # Again, pick a license
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3',      #Specify which pyhton versions that you want to support
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: 3.5',
    'Programming Language :: Python :: 3.6',
  ],
)
