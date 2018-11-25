platform :ios, '10.0'

target 'TrustKeystore' do
  use_frameworks!

  pod 'BigInt', inhibit_warnings: true
  pod 'CryptoSwift', '~> 0.10.0'
  pod 'TrezorCrypto', '~> 0.0.9', inhibit_warnings: true
  pod 'TrustCore', :git=>'https://github.com/TrustWallet/trust-core', :branch=> 'master', inhibit_warnings: true
  pod 'SwiftLint'

  target 'KeystoreBenchmark'
  target 'TrustKeystoreTests'
end
