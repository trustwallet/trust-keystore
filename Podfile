platform :ios, '9.0'

target 'TrustKeystore' do
  use_frameworks!
  pod 'CryptoSwift'
  pod 'secp256k1_ios', :git => 'https://github.com/shamatar/secp256k1_ios.git', inhibit_warnings: true

  target 'KeystoreBenchmark'
  target 'TrustKeystoreTests'
end
