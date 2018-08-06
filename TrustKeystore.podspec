Pod::Spec.new do |s|
  s.name         = 'TrustKeystore'
  s.version      = '0.5.0'
  s.summary      = 'A general-purpose Ethereum keystore for managing wallets.'
  s.homepage     = 'https://github.com/TrustWallet/trust-keystore'
  s.license      = 'GPL'
  s.authors      = { 'Alejandro Isaza' => 'al@isaza.ca' }
  
  s.ios.deployment_target = '10.0'

  s.source       = { git: 'https://github.com/TrustWallet/trust-keystore.git', tag: s.version }
  s.source_files = "Sources/**/*.swift"

  s.dependency 'BigInt'
  s.dependency 'CryptoSwift'
  s.dependency 'TrezorCrypto', '~> 0.0.6'
  s.dependency 'TrustCore', '~> 0.2.1'

  s.pod_target_xcconfig = { 'SWIFT_OPTIMIZATION_LEVEL' => '-Owholemodule' }
end
