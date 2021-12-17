using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DidiSoft.Pgp;
using System.Security.Principal;
using System.IO;





//当前登录的用户信息
public class User
{
    private String username;//用户名
    private SecurityIdentifier sid;//用户安全标识符
    private String userID;
    private string[] all_Authorized_Users;
    private string[] all_Authorized_Uers_PublicKey;//所有用户目录文件

    public User()
    {
        username = Environment.UserName;
        WindowsIdentity windowsIdentity = WindowsIdentity.GetCurrent();
        sid = windowsIdentity.User;
        userID = get_userID();
        Console.WriteLine("当前用户信息");
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
        Console.WriteLine($"当前活动用户名为：{username}\n安全标识符为：{sid}\n当前userID为：{ userID}");
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");

    }


    ~User() //析构函数，保证释放敏感信息
    {

    }
    public String get_username()
    {
        return username;
    }
    public SecurityIdentifier get_sid()
    {
        return sid;
    }
    public String get_userID()
    {
        PGPLib pgp = new PGPLib();
        pgp.Hash = HashAlgorithm.MD5;
        userID = sid.GetHashCode().ToString();
        return userID;
    }
    public string[] get_all_Authorized_Users()
    {
        return all_Authorized_Users;
    }

    public string[] get_all_Authorized_Uers_PublicKey()
    {
        return all_Authorized_Uers_PublicKey;
    }

    //设置能够访问到的all_Authorized_Uers_PublicKey;
    public void User_Authorization()
    {
        string[] all_Uers_pathString = Directory.GetDirectories(Global.pathString);//用户文件夹目录

        if (all_Uers_pathString.Length == 1)
        {
            Console.WriteLine("目前该文件系统未检测到其他用户");
        }

        List<string> _ulist = new List<string> { Environment.UserName };
        List<string> _list = new List<string> { Path.Combine(Global.pathStringKey, "public_key_exported.asc") };


        foreach (string element in all_Uers_pathString)
        {
            String name = Path.GetFileName(element);
            String publicKey = Path.Combine(Global.pathString, name, Global.folderName1, "public_key_exported.asc");//用户公钥文件
            if (name != Environment.UserName && File.Exists(publicKey))
            {
                Console.WriteLine("检测到用户{0}", name);
                Console.WriteLine("您是否要为用户{0}开放该文件的调阅权限？（Y/N）", name);
                String answer = Console.ReadLine();
                while (true)
                {
                    if ((answer == "Y") || (answer == "y"))
                    {
                        _ulist.Add(name);
                        _list.Add(publicKey);
                        Console.WriteLine("为用户{0}开放该文件的调阅权限成功", name);
                        break;
                    }
                    else if ((answer == "N") || (answer == "n"))
                    {
                        Console.WriteLine("为用户{0}开放该文件的调阅权限失败", name);
                        break;
                    }
                    else
                    {
                        Console.WriteLine("请正确输入！");
                        answer = Console.ReadLine();
                    }
                }
              
            }
        }
        all_Authorized_Users = _ulist.ToArray();
        all_Authorized_Uers_PublicKey = _list.ToArray();
    }

    public void detect_All_User_Public_key()
    {
        List<string> _ulist = new List<string> {};
        List<string> _list = new List<string> {};
        
        string[] all_Uers_pathString = Directory.GetDirectories(Global.pathString);//用户文件夹目录
        foreach (string element in all_Uers_pathString)
        {
            String name = Path.GetFileName(element);
            String publicKey = Path.Combine(Global.pathString, name, Global.folderName1, "public_key_exported.asc");//用户公钥文件
            if (File.Exists(publicKey))
            {
                _ulist.Add(name);
                _list.Add(publicKey);
            }
            
        }
        all_Authorized_Users = _ulist.ToArray();
        all_Authorized_Uers_PublicKey = _list.ToArray();
    }

}

//文件位置
public class Global
{
    public static String baseName = "D:\\";
    public static String folderName = "OpenPGP_File_Manage_show";
    public static String folderName1 = "Key";
    public static String folderName2 = "File";

    public static String pathString = System.IO.Path.Combine(baseName, folderName);//总文件夹
    public static String pathStringUser = System.IO.Path.Combine(pathString, Environment.UserName);//用户文件夹
    public static String pathStringKey = System.IO.Path.Combine(pathStringUser, folderName1);//用户密钥文件夹
    public static String pathStringFile = System.IO.Path.Combine(pathStringUser, folderName2);//用户文件文件夹

    public Global()
    {
        Console.WriteLine("/***************************************************************/");
        Console.WriteLine("*              本项目为基于OpenPGP的文件管理系统                *");
        Console.WriteLine("/***************************************************************/\n");
        set_baseName();

        Console.WriteLine("\n应用所创建的文件夹信息");
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
        System.IO.Directory.CreateDirectory(pathString);
        Console.WriteLine("在\"{0}\" 创建了文件夹：\"基于OpenGPG的文件系统\"的总文件夹\n", pathString);

        System.IO.Directory.CreateDirectory(pathStringUser);
        Console.WriteLine("在\"{0}\" 创建了文件夹：用户{1}的用户文件夹\n", pathStringUser, Environment.UserName);

        System.IO.Directory.CreateDirectory(pathStringKey);
        Console.WriteLine("在\"{0}\" 创建了文件夹：用户{1}的密钥（可以导出公钥）文件夹\n", pathStringKey,Environment.UserName);

        System.IO.Directory.CreateDirectory(pathStringFile);
        Console.WriteLine("在\"{0}\" 创建了文件夹：用户{1}的文件（加密、解密后的文件）的文件夹", pathStringFile, Environment.UserName);
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");

    }

    ~Global()//析构函数，保证释放敏感信息
    {

    }
    public void set_baseName()
    {
        Console.WriteLine("请输入项目文件夹的存放位置（默认：D:\\）,输入q可跳过");
        String basename = Console.ReadLine();
        if (basename=="q")
        {
            return;
        }
        else
        {
            baseName = basename;
            pathString = System.IO.Path.Combine(baseName, folderName);//总文件夹
            pathStringUser = System.IO.Path.Combine(pathString, Environment.UserName);//用户文件夹
            pathStringKey = System.IO.Path.Combine(pathStringUser, folderName1);//用户密钥文件夹
            pathStringFile = System.IO.Path.Combine(pathStringUser, folderName2);//用户文件文件夹
        }
    }
}

public class ModeManage
{
    ~ModeManage()//析构函数，保证释放敏感信息
    {

    }
    public int mode_input(User user)
    {
        while (true)
        {
            Console.WriteLine("原理展示请按1，存储文件请按2，调阅文件请按3");
            String Mode = Console.ReadLine();
            if (Mode == "1")
            {
                Console.WriteLine("\n原理展示");
                Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
                Console.WriteLine("请任意输入想要加密的内容，以另起一行输入\":wq\"结束");
                return 1;
            }
            else if (Mode == "2")
            {
                Console.WriteLine("\n文件存储");
                Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
                Console.WriteLine("存储文件的安全模式：仅自己请按1，多用户请按2");
                while (true)
                { 
                    String SubMode = Console.ReadLine();
                    if (SubMode == "1") {
                        Console.WriteLine("该文件由用户{0}创建，并且只能由用户{0}查看", Environment.UserName);
                        Console.WriteLine("请输入文件路径");
                        return 21;
                    }
                    else if(SubMode == "2")
                    {
                        user.User_Authorization();
                        Console.WriteLine("请输入文件路径");
                        return 22;
                    }
                    else
                    {
                        Console.WriteLine("请重新输入！");
                    }
                }
            }

            else if (Mode == "3")
            {
                Console.WriteLine("\n文件调阅");
                Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
                Console.WriteLine("请输入文件路径(后缀为.gpg)");
                return 3;
            }
            else
            {
                Console.WriteLine("请重新输入！");
            }
        }
    }
       
    public void mode_control(int Mode,User user,String passwd)
    {
        if (Mode == 1)
        {
            //键盘读入
            String text = "";
            String input = Console.ReadLine();
            String next = Console.ReadLine();
            while (true)
            {
                if (next == ":wq")
                {
                    text = text + input;
                    break;
                }
                else
                {
                    text = text + input + "\r\n";
                }

                input = next;
                next= Console.ReadLine();
            }

            //签名加密字符串
            FileManage fileManage = new FileManage();
            String after_string = fileManage.SignAndEncryptString(text, passwd,user.get_userID());
            Console.WriteLine("\n键盘输入的字符串为:\n{0}\n\n用您的私钥先签名，再用您的公钥后加密，得到的字符串为\n{1}", text, after_string);

            //解密并验证签名

            fileManage.DecryptAndVerifyString(after_string, passwd,user.get_userID());

            Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
        }
        else if (Mode == 21)
        {
            String File = Console.ReadLine();
            while (true)
            {
                if (System.IO.File.Exists(File))
                {
                    //文件签名加密
                    FileManage fileManage = new FileManage();
                    user.detect_All_User_Public_key();
                    string output_file = fileManage.SignAndEncryptSinge(passwd, File, user.get_userID());
                    bool check = fileManage.Verify(passwd, output_file, user.get_all_Authorized_Uers_PublicKey(), user.get_all_Authorized_Users(), user.get_userID());
                    if (check == false)
                    {
                        ClearTool clearTool = new ClearTool();
                        clearTool.ClearDeletFile(output_file);
                    }
                    else
                    {
                        Console.WriteLine("文件存储成功，并由用户\"{0}\"签名，在\"{1}\"中", Environment.UserName, output_file);
                    }
                    //fileManage.SignAndEncryptMultiple(passwd, File);
                    Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
                    break;
                }
                else
                {
                    Console.WriteLine("文件不存在，请重新输入文件路径");
                    File = Console.ReadLine();
                }
            }

        }
        else if (Mode == 22)
        {
            String File = Console.ReadLine();
            while (true)
            {
                if (System.IO.File.Exists(File))
                {
                    //文件签名加密
                    FileManage fileManage = new FileManage();
                    user.detect_All_User_Public_key();
                    string output_file=fileManage.SignAndEncryptMultiple(passwd, File, user.get_all_Authorized_Uers_PublicKey(), user.get_userID());
                    bool check= fileManage.Verify(passwd, output_file, user.get_all_Authorized_Uers_PublicKey(), user.get_all_Authorized_Users(), user.get_userID());
                    if (check == false)
                    {
                        ClearTool clearTool = new ClearTool();
                        clearTool.ClearDeletFile(output_file);
                    }
                    else
                    {
                        Console.WriteLine("文件存储成功，并由用户\"{0}\"签名，在\"{1}\"中", Environment.UserName, output_file);
                    }
                    Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
                    break;
                }
                else
                {
                    Console.WriteLine("文件不存在，请重新输入文件路径");
                    File = Console.ReadLine();
                }
            }

        }
        else if (Mode == 3)
        {
            String File = Console.ReadLine();
            while (true)
            {
                if (System.IO.File.Exists(File))
                {
                    //文件签名加密
                    FileManage fileManage = new FileManage();
                    user.detect_All_User_Public_key();

                    Console.WriteLine(user.get_all_Authorized_Users().Length);
                    fileManage.DecryptAndVerify(passwd, File, user.get_all_Authorized_Uers_PublicKey(), user.get_all_Authorized_Users(), user.get_userID());
                    Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
                    break;
                }
                else
                {
                    Console.WriteLine("文件不存在，请重新输入文件路径");
                    File = Console.ReadLine();
                }
            }
        }
    }

}




//主函数
namespace OpenPGP_File_Manage
{
    class Program
    {
        ~Program()//析构函数，保证释放敏感信息
        {
        }
        static void Main(string[] args)
        {
            //展示文件夹创建
            Global global = new Global();
            //用户创建
 
            User user = new User();
            String userID = user.get_userID();
            //密钥生成和导出
            KeyManage keyManage = new KeyManage();
            //密码唯一，且由用户的用户名和安全序列号唯一生成
            String passwd = ( user.get_username()+ user.get_sid()).GetHashCode().ToString();
            keyManage.GenerateKeyPairRSA(userID,passwd);
            keyManage.ExportPublicKey(userID,passwd);
            //keyManage.ExportPrivateKey(userID, passwd);//私钥敏感信息不能导出
            keyManage.KeyStoreListKeys(passwd);

            //模式选择：原理展示/存储模式/调阅模式
            //用户界面
            while (true)
            {
                ModeManage modeManage = new ModeManage();
                int Mode = modeManage.mode_input(user);
                modeManage.mode_control(Mode, user, passwd);
                Console.WriteLine("程序已结束，按q退出，按其他任意键返回用户界面...");
                if (Console.ReadLine() == "q")
                    break;
            }
        }
            
            
       

    }
}



 
//基于RSA生成密钥
public class KeyManage
{
    ~KeyManage()//析构函数，保证释放敏感信息
    {

    }
    //RSA密钥生成
    public void GenerateKeyPairRSA(String userID, String passwd)
    {
        Console.WriteLine("生成用户密钥");
        Console.WriteLine("-----------------------------------------------------------------------------------------------------------");
        // initialize the key store where the generated key
        // will be produced, if the file does not exist
        // it will be created
        String file = System.IO.Path.Combine(Global.pathStringKey, "key.store");
        if (!System.IO.File.Exists(file))
        {
            KeyStore ks = new KeyStore(@file, passwd);

            // Preferred symmetric key algorithms for this key
            CypherAlgorithm[] cypher = { CypherAlgorithm.CAST5,
                                 CypherAlgorithm.AES_128 };

            // Preferred digital signature (hash) algorithms for this key
            HashAlgorithm[] hashing = { HashAlgorithm.SHA1,
                                    HashAlgorithm.MD5,
                                    HashAlgorithm.SHA256 };

            // Preferred compression algorithms for this key
            CompressionAlgorithm[] compression =
                        { CompressionAlgorithm.ZIP,
                    CompressionAlgorithm.UNCOMPRESSED};

            int keySizeInBits = 2048;
            ks.GenerateKeyPair(keySizeInBits, userID, KeyAlgorithm.RSA, passwd, compression, hashing, cypher);

            // Now we can use the key from the KeyStore or export it 
            Console.WriteLine("用户{0}的密钥（公私钥）已生成，在\"{1}\"中\n", Environment.UserName, file);
        }
        else
        {
            Console.WriteLine("用户{0}的密钥已存在，在\"{1}\"中\n", Environment.UserName,file);
            return;
        }
    }

    //导出公钥
    public void ExportPublicKey(String userID,String passwd)
    {
        // initialize the KeyStore
        String file_store = System.IO.Path.Combine(Global.pathStringKey, "key.store");
        String file_public_key = System.IO.Path.Combine(Global.pathStringKey, "public_key_exported.asc");


        KeyStore ks = KeyStore.OpenFile(@file_store, passwd);
        
        // should the exported files be ASCII or binary
        bool asciiArmored = true;
       
        // export both public and secret key with all sub keys in one file
        if(!System.IO.File.Exists(file_public_key))
            ks.ExportPublicKey(@file_public_key, userID, asciiArmored);
        Console.WriteLine("用户{0}的公钥已导出，在\"{1}\"中\n", Environment.UserName, file_public_key);
    }
   
    //导出私钥
    public void ExportPrivateKey(String userID, String passwd)
    {
        String file_store = System.IO.Path.Combine(Global.pathStringKey, "key.store");
        String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        // initialize the key store
        KeyStore ks = KeyStore.OpenFile(@file_store, passwd);

        // should the exported files be ASCII or binary
        bool asciiArmored = true;

        // export secret key, this is usually our own key.
        ks.ExportPrivateKey(@file_private_key, userID, asciiArmored);
    }


    //下面的示例以类似于 GnuPG/gpg 的方式列出并打印密钥：
    public void KeyStoreListKeys(String passwd)
    {
        Console.WriteLine("当前密钥信息为：");
        String file = System.IO.Path.Combine(Global.pathStringKey, "key.store");
        // initialize the key store
        KeyStore ks = KeyStore.OpenFile(file, passwd);

        KeyPairInformation[] keys = ks.GetKeys();

        StringBuilder sb = new StringBuilder();
        sb.Append("Username".PadRight(15));
        sb.Append("Type".PadRight(10));
        sb.Append("Key Id".PadRight(30));
        sb.Append("Created".PadRight(20));
        sb.Append("User Id");
        Console.WriteLine(sb.ToString());

        foreach (KeyPairInformation key in keys)
        {
            sb.Remove(0, sb.Length);
            sb.Append(Environment.UserName.PadRight(15));
            String keyType = null;
            if (key.HasPrivateKey)
            {
                keyType = "pub/sec";
            }
            else
            {
                keyType = "pub";
            }
            sb.Append(keyType.PadRight(10));

            sb.Append(Convert.ToString(key.KeyId).PadRight(30));
            sb.Append(key.CreationTime.ToShortDateString().PadRight(20));

            foreach (String id in key.UserIds)
            {
                sb.Append(id);
            }

            Console.WriteLine(sb.ToString());
            Console.WriteLine("-----------------------------------------------------------------------------------------------------------\n");
        }
    }
}



public class FileManage
{
    ~FileManage()//析构函数，保证释放敏感信息
    {

    }
    //签名和加密（多人）
    public string SignAndEncryptMultiple(String passwd, String File, string[] all_Authorized_Uers_PublicKey, String userID)
    {
        //获取文件名（不含拓展名）
        String extension = Path.GetExtension(File);
        String fileNameWithoutExtension = Path.GetFileNameWithoutExtension(File);// 没有扩展名的文件名 "default"
        String fileNameRandom = Path.GetRandomFileName();
        String fileNameRandomWithoutExtension = Path.GetFileNameWithoutExtension(fileNameRandom);
        String newFile = fileNameWithoutExtension + fileNameRandomWithoutExtension + extension + ".gpg";

        // create an instance of the library
        PGPLib pgp = new PGPLib();
        // ASCII armor or binary
        bool asciiArmor = true;
        // append integrity protection check, set to true for compatibility with GnuPG 2.2.8+
        bool withIntegrityCheck = false;


        //文件目录
        string[]  input_file = { @File };
        String file_public_key = System.IO.Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        String output_file = System.IO.Path.Combine(Global.pathStringFile, newFile);
        string[] recipientsPublicKeys = all_Authorized_Uers_PublicKey;

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd);//导出私钥
        ClearTool clearTool = new ClearTool();

        pgp.SignAndEncryptFiles(@input_file,file_private_key,passwd, recipientsPublicKeys, @output_file,asciiArmor, withIntegrityCheck);

        clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息
        return output_file;

    }

    //签名和加密（单人）
    public string SignAndEncryptSinge(String passwd,String File, String userID)
    {
        //获取文件名（不含拓展名）
        String extension=Path.GetExtension(File);
        String fileNameWithoutExtension = Path.GetFileNameWithoutExtension(File);// 没有扩展名的文件名 "default"
        String fileNameRandom = Path.GetRandomFileName();
        String fileNameRandomWithoutExtension = Path.GetFileNameWithoutExtension(fileNameRandom);
        String newFile = fileNameWithoutExtension + fileNameRandomWithoutExtension +extension+ ".gpg";


        // create an instance of the library
        PGPLib pgp = new PGPLib();
        // is output ASCII or binary
        bool asciiArmor = true;
        // should integrity check information be added, set to true for compatibility with GnuPG 2.2.8+
        bool withIntegrityCheck = false;

        
        //文件目录
        String input_file = File;
        String file_public_key = System.IO.Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        String output_file = System.IO.Path.Combine(Global.pathStringFile, newFile);

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd);//导出私钥
        ClearTool clearTool = new ClearTool();

        // sign and encrypt
        pgp.SignAndEncryptFile(@input_file,
                                @file_private_key,
                                passwd,
                                @file_public_key,
                                @output_file,
                                asciiArmor,
                                withIntegrityCheck);

        clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息

        

        return output_file;
    }

    public String SignAndEncryptString(String plainText,String passwd, String userID)
    {
            // create an instance of the library
            PGPLib pgp = new PGPLib();
        String file_public_key = System.IO.Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd);//导出私钥
        ClearTool clearTool = new ClearTool();

        // sign and enrypt
        String encryptedAndSignedString =
                 pgp.SignAndEncryptString(plainText,
                        new FileInfo(file_private_key),
                        passwd,
                        new FileInfo(file_public_key));

        clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息
        return encryptedAndSignedString;
    }

    public bool Verify(String passwd, String File, string[] All_User_Public_key, string[] All_Users, String userID)
    {
        String originalFile = Path.GetFileNameWithoutExtension(File);
        String extension= Path.GetExtension(File); //-->.txt
        String filetmp = originalFile + "Tmp" + extension;
        // create an instance of the library
        PGPLib pgp = new PGPLib();

        //文件目录
        String input_file = File;//gpg
        String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        String output_file = System.IO.Path.Combine(Global.pathStringFile, filetmp);

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd);//导出私钥
        ClearTool clearTool = new ClearTool();

        string user_tmp="错误";
        for (int i = 0; i < All_Users.Length; i++)
        {
            // check the signature and extract the data 
            //The supplied data is not only signed but also encrypted. Please use the DecryptAndVerify or Decrypt methods in order to extract the encrypted contents.”
            //因此只能先解密再验证签名
            SignatureCheckResult signatureCheck =
                pgp.DecryptAndVerifyFile(@input_file,
                                @file_private_key,
                                passwd,
                                @All_User_Public_key[i],
                                @output_file);


            if (signatureCheck == SignatureCheckResult.SignatureVerified && All_Users[i] == Environment.UserName)
            {
                clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息
                clearTool.ClearDeletFile(output_file);
                Console.WriteLine($"身份认证成功，您的身份为{All_Users[i]},创建文件成功");
                return true;

            }
            user_tmp = All_Users[i];
        }
        clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息
        clearTool.ClearDeletFile(output_file);
        Console.WriteLine($"身份认证失败，您的身份为{user_tmp},创建文件失败");
                return false;
    }

    public void DecryptAndVerify(String passwd, String File,string[] All_User_Public_key,string[] All_Users, String userID)
    {
        String originalFile = Path.GetFileNameWithoutExtension(File);
        // create an instance of the library
        PGPLib pgp = new PGPLib();



        //文件目录
        String input_file = File;//gpg
        String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        String output_file = System.IO.Path.Combine(Global.pathStringFile, originalFile);

        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd);//导出私钥
        ClearTool clearTool = new ClearTool();

        // decrypt and obtain the original file name
        // of the decrypted file
        string originalFileName =
                    pgp.DecryptFile(@input_file,
                                        @file_private_key,
                                        passwd,
                                        @output_file);


        Console.WriteLine("您的身份为用户\"{0}\"", Environment.UserName);
        Console.WriteLine("文件调阅成功，原文件名为{0},解密后的文件在{1}中",originalFileName,output_file);

        for(int i = 0; i < All_Users.Length; i++)
        {
            // check the signature and extract the data 
            //The supplied data is not only signed but also encrypted. Please use the DecryptAndVerify or Decrypt methods in order to extract the encrypted contents.”
            //因此只能先解密再验证签名
            SignatureCheckResult signatureCheck =
                pgp.DecryptAndVerifyFile(@input_file,
                                @file_private_key,
                                passwd,
                                @All_User_Public_key[i],
                                @output_file);

            
            if (signatureCheck == SignatureCheckResult.SignatureVerified)
            {
                Console.WriteLine("签名验证成功，该文件是由用户{0}创建的" , All_Users[i]);
                clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息
                break;
            }
            else if (signatureCheck == SignatureCheckResult.NoSignatureFound)
            {
                Console.WriteLine("此文件未数字签名");
                clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息
                break;
            }
            else if (signatureCheck == SignatureCheckResult.SignatureBroken)
            {
                Console.WriteLine("文件的签名已损坏或伪造 ");
                clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息
                break;
            }

            else if (i== All_Users.Length-1 && signatureCheck == SignatureCheckResult.PublicKeyNotMatching)
            {
                Console.WriteLine("提供的公钥与签名不匹配");
                clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息
            }

        }
    }

    public void DecryptAndVerifyString(String signedAndEncryptedMessage,String passwd, String userID)
    {

        String file_public_key = System.IO.Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");

        String plainTextExtracted;

        // create an instance of the library
        PGPLib pgp = new PGPLib();


        KeyManage keyManage = new KeyManage();
        keyManage.ExportPrivateKey(userID, passwd);//导出私钥
        ClearTool clearTool = new ClearTool();

        
        // decrypt and verify
        SignatureCheckResult signatureCheck =
            pgp.DecryptAndVerifyString(signedAndEncryptedMessage,
                     new FileInfo(@file_private_key),
                     passwd,
                     new FileInfo(@file_public_key),
                     out plainTextExtracted);

        clearTool.ClearDeletFile(file_private_key);//删除私钥敏感信息

        // print the results
        if (signatureCheck == SignatureCheckResult.SignatureVerified)
        {
            Console.WriteLine("签名验证成功");
        }
        else if (signatureCheck == SignatureCheckResult.SignatureBroken)
        {
            Console.WriteLine("文件的签名已损坏或伪造 ");
        }
        else if (signatureCheck == SignatureCheckResult.PublicKeyNotMatching)
        {
            Console.WriteLine("提供的公钥与签名不匹配");
        }
        else if (signatureCheck == SignatureCheckResult.NoSignatureFound)
        {
            Console.WriteLine("此文件未数字签名");
        }


        Console.WriteLine("用您的私钥先解密，再用您的公钥验证签名，得到的字符串为\n{0}", plainTextExtracted);
    }


}


public class ClearTool
{
    ~ClearTool()
    {

    }
    /// <summary>
    /// 清空目录或文件
    /// </summary>
    public void ClearDelet(string path)
    {
        if (File.Exists(path)) ClearDeletFile(path);
        if (Directory.Exists(path)) ClearDeletDirectory(path);
    }

    /// <summary>
    /// 先清空目录中的所有文件和子目录内容，再删除当前目录
    /// </summary>
    public void ClearDeletDirectory(string dir)
    {
        if (Directory.Exists(dir))
        {
            // 清除目录下的所有文件
            foreach (String iteam in Directory.GetFiles(dir))
            {
                ClearDeletFile(iteam);
            }

            // 清除目录下的所有子目录
            foreach (String iteam in Directory.GetDirectories(dir))
            {
                ClearDeletDirectory(iteam);
            }

            String newName = System.IO.Directory.GetParent(dir).FullName + "\\$";
            while (File.Exists(newName)) newName += "$";

            // 清除当前目录
            Directory.Move(dir, newName);   // 重命名当前目录，清除目录名信息
            Directory.Delete(newName);      // 清除当前目录
        }
    }

    /// <summary>
    /// 先清空文件内容，再删除
    /// </summary>
    public void ClearDeletFile(string file)
    {
        ClearFile(file);                // 清空文件内容
        if (File.Exists(file))
        {
            String newName = System.IO.Directory.GetParent(file).FullName + "\\$";
            while (File.Exists(newName)) newName += "$";

            File.Move(file, newName);   // 重命名文件，清除文件名称信息
            File.Delete(newName);       // 删除文件
        }
    }

    /// <summary>
    /// 清空文件内容
    /// </summary>
    public static void ClearFile(string file)
    {
        if (File.Exists(file))
        {
            int SIZE = 1024 * 10240;
            byte[] array = new byte[SIZE];
            array.Initialize();

            FileStream s = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite, SIZE, FileOptions.RandomAccess);

            // 清空原有文件内容
            while (s.Position + SIZE <= s.Length - 1)
            {
                s.Write(array, 0, SIZE);
            }
            int reminds = (int)(s.Length - s.Position);
            if (reminds > 0) s.Write(array, 0, reminds);

            // 清除文件长度信息
            s.SetLength(0);
            s.Close();
        }
    }

}


/*
            /*
                //确立文件名
                String fileNameRandom = Path.GetRandomFileName();
                String fileNameRandomWithoutExtension = Path.GetFileNameWithoutExtension(fileNameRandom);
                String newFile = fileNameRandomWithoutExtension + ".pgp";
                String path = Path.Combine(Global.pathStringFile, newFile);

                //写数据
                FileInfo finfo = new FileInfo(path);
                if (finfo.Exists)
                {
                    finfo.Delete();
                }
                using (FileStream fs = finfo.OpenWrite())
                {
                    //根据上面创建的文件流创建写数据流 
                    StreamWriter w = new StreamWriter(fs);
                    //设置写数据流的起始位置为文件流的末尾 
                    w.BaseStream.Seek(0, SeekOrigin.End);
                    w.Write(text);
                    //清空缓冲区内容，并把缓冲区内容写入基础流 
                    w.Flush();
                    //关闭写数据流 
                    w.Close();
                }
                Console.WriteLine("文件存储成功，并由用户\"{0}\"签名，在\"{1}\"中", Environment.UserName, path);
 *  //签名
    public void Sign(String passwd, String File)
        {
            Console.WriteLine("为用户{0}存储的文件进行签名", Environment.UserName);
            // create an instance of the library
            PGPLib pgp = new PGPLib();
            // should the output be ASCII or binary
            bool asciiArmor = true;
            String input_file = File;
            String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");
            String output_file = System.IO.Path.Combine(Global.pathStringFile, "OUTPUT.pgp");
            pgp.SignFile(@input_file,
                         @file_private_key,
                         passwd,
                         output_file,
                         asciiArmor);
        }
    //签名验证
        public void Verify()
        {
            // create an instance of the library
            PGPLib pgp = new PGPLib();

            String input_file = System.IO.Path.Combine(Global.pathStringFile, "OUTPUT2.txt");
            String file_public_key = System.IO.Path.Combine(Global.pathStringKey, "public_key_exported.asc");
            String output_file = System.IO.Path.Combine(Global.pathStringFile, "OUTPUT.pgp");
            // check the signature and extract the data 
            SignatureCheckResult signatureCheck =
                pgp.VerifyFile(@output_file,
                                @file_public_key,
                                input_file);

            if (signatureCheck == SignatureCheckResult.SignatureVerified)
            {
                Console.WriteLine("Signare OK");
            }
            else if (signatureCheck == SignatureCheckResult.SignatureBroken)
            {
                Console.WriteLine("Signare of the message is either broken or forged");
            }
            else if (signatureCheck == SignatureCheckResult.PublicKeyNotMatching)
            {
                Console.WriteLine("The provided public key doesn't match the signature");
            }
            else if (signatureCheck == SignatureCheckResult.NoSignatureFound)
            {
                Console.WriteLine("This message is not digitally signed");
            }
        }

    //加密文件
    public void EncryptFile(String File)
    {
        //获取文件名（不含拓展名）
        String fileNameWithoutExtension = Path.GetFileNameWithoutExtension(File);// 没有扩展名的文件名 "default"
        String fileNameRandom = Path.GetRandomFileName();
        String fileNameRandomWithoutExtension = Path.GetFileNameWithoutExtension(fileNameRandom);
        String newFile = fileNameWithoutExtension + fileNameRandomWithoutExtension + ".gpg";

        // create an instance of the library
        PGPLib pgp = new PGPLib();

        // specify should the output be ASCII or binary
        bool asciiArmor = true;
        // should additional integrity information be added
        // set to true for compatibility with GnuPG 2.2.8+
        bool withIntegrityCheck = false;

        //文件目录
        String input_file = File;
        String file_public_key = System.IO.Path.Combine(Global.pathStringKey, "public_key_exported.asc");
        String output_file = System.IO.Path.Combine(Global.pathStringFile, newFile);

        pgp.EncryptFile(@input_file,
                        @file_public_key,
                        @output_file,
                        asciiArmor,
                        withIntegrityCheck);

        Console.WriteLine("文件存储成功，在\"{0}\"中", output_file);
    }

    //解密文件
    public void DecryptFile(String passwd)
    {
        // initialize the library
        PGPLib pgp = new PGPLib();
        String input_file = System.IO.Path.Combine(Global.pathStringFile, "OUTPUT.txt");
        String file_private_key = System.IO.Path.Combine(Global.pathStringKey, "private_key_exported.asc");
        String output_file = System.IO.Path.Combine(Global.pathStringFile, "OUTPUT.pgp");

        string inputFileLocation = @output_file;
        string privateKeyLocation = @file_private_key;
        string privateKeyPassword = passwd;
        string outputFile = @input_file;

        // decrypt and obtain the original file name
        // of the decrypted file
        string originalFileName =
                    pgp.DecryptFile(inputFileLocation,
                                privateKeyLocation,
                                privateKeyPassword,
                                outputFile);
    }*/
/*
 * 更改密码
// C#
KeyStore ks = KeyStore.OpenFile(@"c:\my.keystore", "my password");
ks.Password = "new password";
ks.Save();
*/
