module se.uu.ub.cora.password {
	requires spring.security.crypto;
	requires org.bouncycastle.provider;

	exports se.uu.ub.cora.password.texthasher;
}