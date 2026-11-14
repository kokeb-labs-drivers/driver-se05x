/**
 * @file policy_rule_invalid_for_class.cpp
 * @brief Must NOT compile: a policy rule the chip does not define for the object class, here
 * ALLOW_KDF (`Rule::Hkdf`) on an EC key pair on applet 7.x (AN12543 Table 15: a symmetric-key
 * rule). The builder's rules are constrained by `RuleAllowedFor`.
 *
 * EXPECT: constraints not satisfied
 */
#include "se05x_policy.hpp"

int main() {
  using Builder = se05x::PolicyBuilder<se05x::AppletGeneration::V7, se05x::ObjectClass::EcKeyPair>;
  const auto policy = Builder{}.ForAllOthers().Allow<se05x::Rule::Hkdf>().Build();
  return policy.ok() ? 0 : 1;
}
