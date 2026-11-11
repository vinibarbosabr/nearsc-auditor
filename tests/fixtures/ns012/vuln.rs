// NS012: a privileged setter with no access control. The name prefix
// reveals the intent the guard must enforce; any account can call it.
pub fn set_fee(&mut self, fee: u32) {
    self.fee = fee;
}
