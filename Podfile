platform :ios, '10.0'

target 'TrustKeystore' do
  use_frameworks!

  pod 'BigInt', inhibit_warnings: true
  pod 'CryptoSwift', '~> 0.10.0'
  pod 'TrezorCrypto', inhibit_warnings: true
  pod 'TrustCore', '~> 0.1.0', inhibit_warnings: true
  pod 'SwiftLint'

  target 'KeystoreBenchmark'
  target 'TrustKeystoreTests'
end
