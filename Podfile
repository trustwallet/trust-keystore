platform :ios, '10.0'

target 'TrustKeystore' do
  use_frameworks!

  pod 'BigInt'
  pod 'CryptoSwift', '~> 0.10.0'
  pod 'TrezorCrypto', inhibit_warnings: true
  pod 'TrustCore', inhibit_warnings: true, path: '../trust-core'
  pod 'SwiftLint'

  target 'KeystoreBenchmark'
  target 'TrustKeystoreTests'
end
