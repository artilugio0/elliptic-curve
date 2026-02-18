package becc

import (
	"math/big"
	"testing"
)

func TestSecp256k1ECCVerify(t *testing.T) {
	tt := []struct {
		msg, key, r, s string
	}{
		{
			msg: "djowigocpv",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "7d843d8a81020f433906c1fcc7cddeeb15f647635c95861cdb86953ad08a6321",
			s:   "bc1a4bf12a593c39b3067b8f4364a1132adacfbcf453f29ca0de7121541010bf",
		},
		{
			msg: "tmdajwcpoqt",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "a101bf69a2a0d72b03834bf77f62fc73d7bf2bbc458ac876c093c6888ce1248a",
			s:   "6c7b7baaabe96c19348301b2f4abc46aa72ed267c595ceca0baf25568db819af",
		},
		{
			msg: "wcxualhzbmwu",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "1460f92816598be896015db76f3feb50aae45ef5eff8eb50b535482a19c7b651",
			s:   "68e090a02f975d547c37e7973c19986550cbd162f7139040f7fda93802a5fe86",
		},
		{
			msg: "eoqiffzzgvvvf",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "c7601f433b3e0249c9e96c61f04fe0619054492d71b44908f27a33e8172163cd",
			s:   "ffb5015db166eb68fb5b3f8bd73c2bb509e861628d7f121db4a5c48695518733",
		},
		{
			msg: "pmerfjndaqbdvd",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "2476f6f4022260a700a415d55aa3a0c61181305d3aaf85ad5797a2a846296569",
			s:   "9c702ebab7d38eaafacd26a91c5ce971e4dd40a398f18dd2c08698a2cd121be7",
		},
		{
			msg: "jqbamrnamlmraib",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "4de7b60adb41bf43d9bbd820c0e84f41f8eae1073c468cde8ceb22de36c55061",
			s:   "54c1f72b5f174bbfa5ee9f3b7302f71805e2a8f1ea1c999e5e32b1065f84f51c",
		},
		{
			msg: "lkiqfaujlcxxqacj",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "1e57d3808656b7755c5d69b0775b70b516be079c3b16916c95ff3970c48567b3",
			s:   "e67eb740eddabd03eef81e86c74e804007921e5b37d0d105aa2df8959fe1b1f3",
		},
		{
			msg: "sxnkwkqnkovrxiobs",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "c58e04bcc3315e7fdf9ea2065494360b91145e8344563ea9a6937ba6f6a8099d",
			s:   "09624f2b0de073ef9dac75297af55bd1f5c33c96fa6183d0a7463bf1a1fb70ff",
		},
		{
			msg: "azozbqijzouahebviu",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "a525dd7c5744ff7057ddaf09391689b5d38f8499c4a060e102c2ed644332c404",
			s:   "164261dfdefffdcc926256999793b920fb9765b654a1c809923b212eba4f7b7c",
		},
		{
			msg: "pfvdmtehtpmuenhfgop",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "7d85554efd109fe2478f7f5a5842713a4ebd0a62e48235a5ae3adfb9eea4ad0a",
			s:   "2a2007ad91fa6463ce4f23db0aeaff35fad4ac7a6619835ad86740cf7db8f6b1",
		},
		{
			msg: "mqzbuyjguimbiuuozywt",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "fc90841929d031f51396aea70a533a246ab51f8fe8f2437e5fd59f1a970711c9",
			s:   "7c756bf4c3c0835d749233628ef9b5fbba719ff7b04d630c7dfb532644086607",
		},
		{
			msg: "hndppmuahnmuuelkojcxw",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "a7402cc21dc35aa4dafd0d5bd524110114271e907dd3de53d41eb1af8fb7c3fe",
			s:   "200bd0d6a789f25985e4e2c0641bbbe724b841c517b4bac1ff888b99402a0ff0",
		},
		{
			msg: "kgjghrgzqygqeheeriqafa",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "12f0a26a70fdf9e83c2ae50f9c4ce3ccc9dee2d28e2a9c79d3deb4c11b2e7a5a",
			s:   "b5783a62672d5059d5adf31797c2966839466b9cd2088fdaafb5ae98f24ff5d8",
		},
		{
			msg: "hrzsyrmymelhwgrohhgcsyh",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "e06de9a748e1b2e96b6b0021feed24d08899d8278fd416917303325f72b44d92",
			s:   "85286c92584ee66f4cdc9fd94e710e1abf4fa9c18250ec4775568ef55636f2b6",
		},
		{
			msg: "siqmaixuiezdlqmmlvyrfbls",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "03e5593b8b9aad4f90c642d74731fd7c2e1c707569cec9f926a775a4902f728a",
			s:   "df9a4367adc4b202f9275852d7e077c2126b0220d0b6caeba645e9be1139bfba",
		},
		{
			msg: "alaqwwocqpiesikoxyhcrhvud",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "47bec5168cb11c2a0287d53710c9af0dad607b77704c8a6ca0046b23e43324ea",
			s:   "7b9599d11ef0cf3eb6e6a09f0ccab94d44de3651b26b8565f412f86ea9d146ce",
		},
		{
			msg: "wvcufojmrzscdgfhdsnitcjslw",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "0695a7615ec0eb9081bc93ed3e71115dd8f3ba7160f70b034e9502d21e94db03",
			s:   "daa14c15396bab89fb755725ebaff9ab82a0666e1b727557634071d716f41e14",
		},
		{
			msg: "whvefuglhsnzbixwtzrjnjiagwm",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "7d360f72859c254f4e6b1cdced2cbf4ec45c3879c6a30380a3bd3037b20cf39a",
			s:   "e3cd5cc41ee224a805fd9b46284d969b5aaa570636e69cf53c9ce92af8d877d9",
		},
		{
			msg: "cdktwyjpjcuimdgrefatzxqxrleo",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "7beaa6f791928efe08d3f61c936c9cab5df500343a6d7062b7a370d824ff8169",
			s:   "db11d8ba04f8a1b00c2784ee9c6870965e7047ac4d7257a15286ad8c8a1fa969",
		},
		{
			msg: "ekhaigfplfxzrnsaszbudsabhssbn",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "6fad7770b55e03fc8038f5892007455145a2ea5a75d80103024babf041aa4ae2",
			s:   "bf315015cb33250e25876557968081241eefbebd20021224f51ceaed511d1730",
		},
		{
			msg: "xjdnpbvbsbjfzwckxqneheikazencf",
			key: "3ce3262f2fba436f7cc4ed0914a6471a2a73fb1accc5f2852951a483efeba817",
			r:   "13719a1caf6270b5485d97087fb5cd83d7024057ddee560f871428e194c4094a",
			s:   "a1ac22e652fc1501b3258fa947a48696d0f92b0deb3434fce99c7b66abef1f31",
		},
	}

	ecc := Secp256k1ECC()

	for _, tc := range tt {
		t.Run(tc.msg, func(t *testing.T) {
			msg := []byte(tc.msg)
			key, _ := new(big.Int).SetString(tc.key, 16)
			r, _ := new(big.Int).SetString(tc.r, 16)
			s, _ := new(big.Int).SetString(tc.s, 16)

			privKey := ecc.NewPrivateKey(key)
			pubKey := privKey.PublicKey()

			sig := NewSignature(r, s)
			if !pubKey.Verify(SHA256, msg, sig) {
				t.Errorf("verification failed")
			}

			msg = append(msg, 'x')
			if pubKey.Verify(SHA256, msg, sig) {
				t.Errorf("verification succeeded with invalid message")
			}
		})
	}
}
