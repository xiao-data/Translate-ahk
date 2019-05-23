#z::
Send ^c
ClipBoard := StrReplace(ClipBoard, "`r`n", " ")
ss := SubStr(ClipBoard, 1, 1)
; enter your appid
appid = 
; enter your secretkey 
secretkey = 
myurl = http://api.fanyi.baidu.com/api/trans/vip/translate
Random, salt ,32768, 65536
sign = %appid%%ClipBoard%%salt%%secretkey%
sign := MD5(sign)
if (Asc(ss) > 0x4e00 and Asc(ss) < 0x9fa5)
{
    SetFormat, integer, H
    ClipBoard := Encode(ClipBoard, "CP65001", "%")
    tolang = en
}
else
    tolang = zh
SetFormat, integer, D
url = %myurl%?q=%ClipBoard%&from=auto&to=%tolang%&appid=%appid%&salt=%salt%&sign=%sign%
try{
whr := ComObjCreate("WinHttp.WinHttpRequest.5.1")
whr.Open("GET", url, true)
whr.Send()
whr.WaitForResponse()
}
catch e{
    msgbox, Non-networked
    Exit
}
rt := whr.ResponseText
pos := RegExMatch(rt, """,""dst"":""(.*)""}\]}")
result := SubStr(rt, pos)
len := StrLen(result)
result := SubStr(result, 10, len-13)
result := StrReplace(result, "`\u","%")
ClipBoard := Decode(result)
msgbox, 0, result, % ClipBoard
; Decode==========
Decode(Str) {
    Pos := 1
    While Pos := RegExMatch(Str, "i)(`%[\da-f]{4})+", Code, Pos)
    {
        VarSetCapacity(Var, StrLen(Code) // 5 * 3, 0), Code := SubStr(Code, 2)
        
        Loop, Parse, Code, `%,
        {
            B_Ind := A_Index
            P := Unicode2UTF8(A_LoopField)
            Loop, Parse, P, `%
                NumPut(A_LoopField, Var, (B_Ind - 1)*3 + A_Index-1, "UChar")
        }
        Decoded := StrGet(&Var, "UTF-8")
        Str := SubStr(Str, 1, Pos-1) . Decoded . SubStr(Str, Pos+StrLen(Code)+1)
        Pos += StrLen(Decoded)+1
    }
    Return, Str
}
; Unicode2UTF8==========
Unicode2UTF8(Str){
    If Strlen(Str) != 4
        Return false
    b1 := "0x"SubStr( Str, 1, 1)
    b2 := "0x"SubStr( Str, 2, 1)
    b3 := "0x"SubStr( Str, 3, 1)
    b4 := "0x"SubStr( Str, 4, 1)
    SetFormat, Integer, H
    utf8_1 := 0xe * 0x10 + b1
    tmp1 := b2 >> 2 
    tmp2 := low2bit(b2)
    tmp3 := b3 >> 2
    tmp4 := low2bit(b3)
    utf8_2 := (0x8 + tmp1) * 0x10 + (tmp2 << 2) + tmp3
    utf8_3 := (0x8 + tmp4) * 0x10 + b4
    result = %utf8_1%`%%utf8_2%`%%utf8_3%
    Return result
}
; low2bit==========
low2bit(Str){
    if Str >= 0xc
        Str := Str - 0xc
    if Str >= 0x8
        Str := Str - 0x8
    if Str >= 0x4
        Str := Str - 0x4
    Return Str
}
; Encode=========
Encode(Str, Encoding, Separator = "")
{
    StrCap := StrPut(Str, Encoding)
    VarSetCapacity(ObjStr, StrCap)
    StrPut(Str, &ObjStr, Encoding)
    Loop, % StrCap - 1
    {
        ObjCodes .= Separator . SubStr(NumGet(ObjStr, A_Index - 1, "UChar"), 3)
    }
    Return, ObjCodes
}
; MD5==========
MD5(string, encoding = "UTF-8")
{
    return CalcStringHash(string, 0x8003, encoding)
}
; CalcStringHash==========
CalcStringHash(string, algid, encoding = "CP65001", byref hash = 0, byref hashlength = 0)
{
    chrlength := (encoding = "CP1200" || encoding = "UTF-16") ? 2 : 1
    length := (StrPut(string, encoding) - 1) * chrlength
    VarSetCapacity(data, length, 0)
    StrPut(string, &data, floor(length / chrlength), encoding)
    return CalcAddrHash(&data, length, algid, hash, hashlength)
}
; CalcAddrHash==========
CalcAddrHash(addr, length, algid, byref hash = 0, byref hashlength = 0)
{
    static h := [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, "a", "b", "c", "d", "e", "f"]
    static b := h.minIndex()
    hProv := hHash := o := ""
    if (DllCall("advapi32\CryptAcquireContext", "Ptr*", hProv, "Ptr", 0, "Ptr", 0, "UInt", 24, "UInt", 0xf0000000))
    {
        if (DllCall("advapi32\CryptCreateHash", "Ptr", hProv, "UInt", algid, "UInt", 0, "UInt", 0, "Ptr*", hHash))
        {
            if (DllCall("advapi32\CryptHashData", "Ptr", hHash, "Ptr", addr, "UInt", length, "UInt", 0))
            {
                if (DllCall("advapi32\CryptGetHashParam", "Ptr", hHash, "UInt", 2, "Ptr", 0, "UInt*", hashlength, "UInt", 0))
                {
                    VarSetCapacity(hash, hashlength, 0)
                    if (DllCall("advapi32\CryptGetHashParam", "Ptr", hHash, "UInt", 2, "Ptr", &hash, "UInt*", hashlength, "UInt", 0))
                    {
                        loop % hashlength
                        {
                            v := NumGet(hash, A_Index - 1, "UChar")
                            o .= h[(v >> 4) + b] h[(v & 0xf) + b]
                        }
                    }
                }
            }
            DllCall("advapi32\CryptDestroyHash", "Ptr", hHash)
        }
        DllCall("advapi32\CryptReleaseContext", "Ptr", hProv, "UInt", 0)
    }
    return o
}
