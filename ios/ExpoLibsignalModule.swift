import ExpoModulesCore

public class ExpoLibsignalModule: Module {
  public func definition() -> ModuleDefinition {
    Name("ExpoLibsignal")

    Function("getTheme") { () -> String in
      "system"
    }
  }
}
