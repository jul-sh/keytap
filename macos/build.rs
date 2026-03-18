fn main() {
    swift_rs::SwiftLinker::new("15")
        .with_package("PasskeyBridge", "swift-lib/")
        .link();
}
