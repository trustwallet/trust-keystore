platform :ios, '9.0'

target 'TrustKeystore' do
  use_frameworks!

  pod 'BigInt'
  pod 'CryptoSwift', '~> 0.8.1'
  pod 'TrezorCrypto', inhibit_warnings: true
  pod 'TrustCore', inhibit_warnings: true
  pod 'SwiftLint'

  target 'KeystoreBenchmark'
  target 'TrustKeystoreTests'
end
