from tkinter import *
from tkinter import messagebox as mb
import random

root = Tk()
root.title("DES")
root.geometry('795x385')
root.configure(background="silver")

###################################___GUI___###################################
#####1_line#####
text_label = Label(root, text="Введите текст (8 символов):", background="silver")
text_label.place(x=5, y=0)

e1_var = StringVar()
e1_var.trace('w', lambda *args: trans_ent_to_bhs())
e1 = Entry(root, textvariable = e1_var, width=40)
e1.place(x=5, y=20)

key_label = Label(root, text="Введите ключ шифрования (7 символов):", background="silver")
key_label.place(x=270, y=0)

e2_var = StringVar()
e2_var.trace('w', lambda *args: key_change())#############################################
e2 = Entry(root, textvariable = e2_var, width=40)
e2.place(x=270, y=20)

keybit_label = Label(root, text="Ключ шифрования с битами четности:", background="silver")
keybit_label.place(x=535, y=0)

e3_var = StringVar()
#e3_var.trace('w', lambda *args: trans_ent_to_bhs())
e3 = Entry(root, textvariable = e3_var, width=40)
e3.place(x=535, y=20)

#2_line
r_var = IntVar()
r_var.set(0)
r1 = Radiobutton(text='Символьное', variable=r_var, value=0, background="silver", command = lambda *args: trans_ent_to_bhs())
r2 = Radiobutton(text='Двоичная система', variable=r_var, value=1 ,background="silver", command = lambda *args: trans_ent_to_bhs())
r3 = Radiobutton(text='Шестнадцатеричная система', variable=r_var, value=2, background="silver", command = lambda *args: trans_ent_to_bhs())
#--------------------------------------
variants_label = Label(root, text="Выбор системы представления", background="silver")
variants_label.place(x=5, y=45)
r1.place(x=5, y=70)
r2.place(x=100, y=70)
r3.place(x=225, y=70)

#3_line
start_data_label = Label(root, text="Исходные данные в выбранной системе", background="silver")

txt_label = Label(root, text="Открытый текст", background="silver")
key1_label = Label(root, text="Ключ шифровния", background="silver")
key2_label = Label(root, text="Ключ с проверкой четности", background="silver")

e_text = Entry(width = 96)
e2_key = Entry(width = 96)
e2_key2 = Entry(width = 96)
#-----------------------------------------
start_data_label.place(x=5, y=100)
txt_label.place(x=5, y=120)
key1_label.place(x=5, y=145)
key2_label.place(x=5, y=170)

e_text.place(x=200, y=120)
e2_key.place(x=200, y=145)
e2_key2.place(x=200, y=170)

#4_line
round_info_label = Label(root, text="Раундовая информация", background="silver")

roundNomer_label = Label(root, text="Раунд", background="silver")
round_text = Entry(width = 4)
button1 = Button(root,text='Следующий раунд',width=15,height=1,background="silver",fg='black',font='arial 8', command=lambda : round_info())
r2_var = IntVar()
#r2_var.set(0)
r21 = Radiobutton(text='Зашифровка', variable=r2_var, value=1, background="silver")
r22 = Radiobutton(text='Расшифровка', variable=r2_var, value=2, background="silver")

l_b_label = Label(root, text="Левый полублок", background="silver")
r_b_label = Label(root, text="Правый поублок", background="silver")
roundkey_label = Label(root, text="Раундовый ключ", background="silver")

l_b_text = Entry(width = 96)
r_b_text = Entry(width = 96)
round_key = Entry(width = 96)
#-----------------------------------------
round_info_label.place(x=5, y=200)

roundNomer_label.place(x=5, y=220)
round_text.place(x=45, y=220)
button1.place(x=85, y=220)
r21.place(x=200, y=220)
r22.place(x=315, y=220)

l_b_label.place(x=5, y=250)
r_b_label.place(x=5, y=275)
roundkey_label.place(x=5, y=300)

l_b_text.place(x=200, y=250)
r_b_text.place(x=200, y=275)
round_key.place(x=200, y=300)

#5_line
encr_label = Label(root, text="Зашифрованный текст:", background="silver")
encr_txt = Entry(width = 96)
#-------------------------------
encr_label.place(x=5, y=350)
encr_txt.place(x=200, y=350)

###################################___Main___###################################
###
#######_______Работа с введенными данными

###Генерация ключей стартовых
def key_gen():
    input_bin_key_56 = ''
    temp_key = 0
    while temp_key < 7:
        temp_s = ''
        for i in range(8):
            temp_s = temp_s + str(random.randint(0, 1))
        if (48 <= int(temp_s, 2) <= 57) or (65 <= int(temp_s, 2) <= 90) or (97 <= int(temp_s, 2) <= 122) or (
                192 <= int(temp_s, 2) <= 255) or (int(temp_s, 2) == 184) or (int(temp_s, 2) == 168):
            input_bin_key_56 += temp_s
            temp_key += 1

    a = translate(input_bin_key_56, 'b', 's')
    c = ctrlBit(input_bin_key_56)
    r = ''
    for i in c:
        r += str(hex(int(i, 2))[2:]).zfill(2)

    e2.delete(0, END)
    e3.delete(0, END)
    e2.insert(0, a)
    e3.insert(0, r)
    if len(e3.get()) > 16:
        e3.delete(0, 16)

#изменение ключа
def key_change():
    if len(e2.get())==7:
        if len(e3.get())>16:
            e3.delete(0,16)
        a = e2.get()
        input_bin_key_56 = translate(a, 's', 'b')
        c = ctrlBit(input_bin_key_56)

        r = ''
        for i in c:
            r += str(hex(int(i, 2))[2:]).zfill(2)
        e3.insert(0, r)
        trans_ent_to_bhs()
    elif len(e2.get())>7:
        mb.showerror('КЕК ПОЛИС', 'Много букав')
        e2.delete(len(e2.get()) - 1, END)
    else:
        e3.delete(0, END)
        e2_key.delete(0, END)
        e2_key2.delete(0, END)
        pass

#перевод
def trans_ent_to_bhs():
    if len(e1.get())<= 16 and len(e2.get())<=7:
        e_text.delete(0, END)
        e2_key.delete(0, END)
        e2_key2.delete(0, END)

        a = e1.get()
        a2 = e2.get()
        a3 = e3.get()

        if r_var.get() == 0:
            a = translate(a, 's', 's')
            a2 = translate(a2, 's', 's')
            a3 = translate(a3, 'h', 's')

            e_text.insert(0, a)
            e2_key.insert(0, a2)
            e2_key2.insert(0, a3)

        elif r_var.get() == 1:
            a = translate(a, 's', 'b')
            a2 = translate(a2, 's', 'b')
            a3 = translate(a3, 'h', 'b')

            e_text.insert(0, a)
            e2_key.insert(0, a2)
            e2_key2.insert(0, a3)

        elif r_var.get() == 2:
            a = translate(a, 's', 'h')
            a2 = translate(a2, 's', 'h')
            a3 = translate(a3, 'h', 'h')

            e_text.insert(0, a)
            e2_key.insert(0, a2)
            e2_key2.insert(0, a3)
    else:
        mb.showerror('КЕК ПОЛИС', 'Много букав')
        e1.delete(len(e1.get()) - 1, END)
        e2.delete(len(e2.get()) - 1, END)
        e3.delete(len(e3.get()) - 1, END)

###Функция перевода в разные системы счисления
def translate(strl, sys1, sys2):
# из двоичной в любую
    if sys1 == 'b':
        if sys2 == 'b':
            return strl
        elif sys2 == 'h':
            out_1 = ''
            temp_1 = [strl[i:i+8] for i in range(0, len(strl), 8)]
            for i in temp_1:
                out_1+=str(hex(int(i,2))[2:]).zfill(2)
            return out_1
        else:
            out_2 = ''
            temp_2 = [strl[i:i+8] for i in range(0, len(strl), 8)]
            for i in temp_2:
                temp_3 =int(i,2)
                if (48<=temp_3<=57) or (65<=temp_3<=90) or (97<=temp_3<=122):
                    out_2+=chr(temp_3)
                elif 192<=temp_3<=255:
                    out_2+=chr(temp_3+848)
                elif temp_3 == 168:
                    out_2+='Ё'
                elif temp_3 == 184:
                    out_2+='ё'
                else:
                    out_2+=chr(temp_3)
            return out_2
# Перевод из симовольной в любую
    elif sys1 == 's':
        if sys2 == 's':
            return strl
        elif sys2 == 'b':
            out_3 = ''
            for i in strl:
                if 1040<=ord(i)<=1103:
                    out_3+=str(bin(ord(i)-848))[2:].zfill(8)
                elif ord(i) == 1105:
                    out_3+='10111000'
                elif ord(i) == 1025:
                    out_3+='10101000'
                else:
                    out_3+=str( bin (   ord (i) )   )[2:].zfill(8)
            return out_3
        else:
            out_4 = ''
            for i in strl:
                if 1040<=ord(i)<=1103:
                    out_4+=str(hex(ord(i)-848))[2:].zfill(2)
                elif ord(i) == 1105:
                    out_4+='b8'
                elif ord(i) == 1025:
                    out_4+='a8'
                else:
                    out_4+=str(hex(ord(i)))[2:].zfill(2)
            return out_4
# Из 16-ричной в любую
    else:
        if sys2 == 'h':
            return strl
        elif sys2 == 's':
            out_5 = ''
            for i in range(0, len(strl), 2):
                temp_4 = strl[i:i+2]
                temp_5 = int(temp_4, 16)
                if 192<=temp_5<=255:
                    out_5+=chr(temp_5+848)
                elif temp_5 == 168:
                    out_5+='Ё'
                elif temp_5 == 184:
                    out_5+='ё'
                else:
                    out_5+=chr(temp_5)
            return out_5
        else:
            out_6 = ''
            for i in range(0, len(strl), 2):
                temp_6 = strl[i:i+2]
                out_6+=str(bin(int(temp_6, 16)))[2:].zfill(8)
            return out_6

###56 в 64
def ctrlBit(strk):
    c = [strk[i:i + 7] for i in range(0, len(strk), 7)]
    count = 0
    for i in c:
        temp_sum = 0
        for j in range(7):
            temp_sum += int(i[j])
        if temp_sum % 2 == 1:
            c[count] = c[count] + '0'
            count += 1
        else:
            c[count] = c[count] + '1'
            count += 1
    return c

###64 в 56
def ctrlBitReverse(strk):
    temp = translate(strk, 'h', 'b')
    b = [temp[i:i + 8] for i in range(0, 64, 8)]
    c = ''
    for i in b:
        c += i[0:7]
    c1 = translate(c, 'b', 's')
    return c1

###############################___шифрование___####################################

def shift(strk, n):
    for i in range(n):
        strk.append(strk.pop(0))
    return strk

def keyPrepare():
    input_Key = translate(e3.get(), 'h', 'b')
    #print(input_Key)
    Key1 = []
    gKey = []
    cArray = []
    dArray = []
    readyKey = []
    # Получение ключа 64 бита
    for i in input_Key: Key1.append(int(i))
    # G матрица первоначальной подготовки ключа
    for i in range(56): gKey.append(Key1[gBox[i] - 1])
    # Получаем заготовки для сдвигов
    c0 = gKey[:28]
    d0 = gKey[28:]
    cArray.append(c0)
    dArray.append(d0)
    for i in range(16):
        hKey = []

        tempC = shift(cArray[i], shiftBox[i])
        cTemp = ''
        tempD = shift(dArray[i], shiftBox[i])
        dTemp = ''

        cArray.append(tempC)
        dArray.append(tempD)

        for j in tempC: cTemp += str(j)
        for k in tempD: dTemp += str(k)
        tempKey = cTemp + dTemp

        for a in range(48): hKey.append(int(tempKey[hBox[a] - 1]))

        readyStrKey = ''
        for y in hKey: readyStrKey += str(y)
        readyKey.append(readyStrKey)

    return readyKey

def crypt():
    l_b_text.delete(0, END)
    r_b_text.delete(0, END)
    round_key.delete(0, END)
    round_text.delete(0, END)
    round_text.insert(0, '0')
    if (r2_var.get() == 1) and ((len(e1.get()) == 8) or (len(e1.get()) == 16)) and (len(e3.get()) == 16):
        keyArray_enc = keyPrepare()
        encryptText, re, le = encrypt(keyArray_enc)
        encr_txt.delete(0, END)
        encr_txt.insert(0, encryptText)
        le.pop(0)
        re.pop(0)
    elif (r2_var.get() == 2) and (len(e1.get()) == 16) and (len(e3.get()) == 16):
        keyArray = keyPrepare()
        keyArrayRevers = list(reversed(keyArray))
        decryptText, rd, ld = decrypt(keyArrayRevers)

        encr_txt.delete(0, END)
        encr_txt.insert(0, decryptText)
        ld.pop(0)
        rd.pop(0)

def decrypt(key):
    inputData = translate(e1.get(), 'h', 'b')
    inputPer = []
    rBlock = []
    lBlock = []
    for i in range(64): inputPer.append(int(inputData[ip[i] - 1]))
    r0 = inputPer[:32]
    l0 = inputPer[32:]
    rBlock.append(r0)
    lBlock.append(l0)
    for i in range(16):
        e = ''
        temp_l = lBlock[i]
        rBlock.append(lBlock[i])
        for q in range(32): e += str(temp_l[eBox[q] - 1])
        ek = str(bin(int(e, 2) ^ int(key[i], 2)))[2:].zfill(48)
        eks = [ek[w:w + 6] for w in range(0, 48, 6)]
        s1 = eks[0]
        s2 = eks[1]
        s3 = eks[2]
        s4 = eks[3]
        s5 = eks[4]
        s6 = eks[5]
        s7 = eks[6]
        s8 = eks[7]
        s1_x = int((s1[0] + s1[5]), 2)
        s1_y = int((s1[1] + s1[2] + s1[3] + s1[4]), 2)

        s2_x = int((s2[0] + s2[5]), 2)
        s2_y = int((s2[1] + s2[2] + s2[3] + s2[4]), 2)

        s3_x = int((s3[0] + s3[5]), 2)
        s3_y = int((s3[1] + s3[2] + s3[3] + s3[4]), 2)

        s4_x = int((s4[0] + s4[5]), 2)
        s4_y = int((s4[1] + s4[2] + s4[3] + s4[4]), 2)

        s5_x = int((s5[0] + s5[5]), 2)
        s5_y = int((s5[1] + s5[2] + s5[3] + s5[4]), 2)

        s6_x = int((s6[0] + s6[5]), 2)
        s6_y = int((s6[1] + s6[2] + s6[3] + s6[4]), 2)

        s7_x = int((s7[0] + s7[5]), 2)
        s7_y = int((s7[1] + s7[2] + s7[3] + s7[4]), 2)

        s8_x = int((s8[0] + s8[5]), 2)
        s8_y = int((s8[1] + s8[2] + s8[3] + s8[4]), 2)

        newS_1 = str(bin(sb1[s1_x][s1_y]))[2:].zfill(4)
        newS_2 = str(bin(sb2[s2_x][s2_y]))[2:].zfill(4)
        newS_3 = str(bin(sb3[s3_x][s3_y]))[2:].zfill(4)
        newS_4 = str(bin(sb4[s4_x][s4_y]))[2:].zfill(4)
        newS_5 = str(bin(sb5[s5_x][s5_y]))[2:].zfill(4)
        newS_6 = str(bin(sb6[s6_x][s6_y]))[2:].zfill(4)
        newS_7 = str(bin(sb7[s7_x][s7_y]))[2:].zfill(4)
        newS_8 = str(bin(sb8[s8_x][s8_y]))[2:].zfill(4)

        pPrepare = newS_1 + newS_2 + newS_3 + newS_4 + newS_5 + newS_6 + newS_7 + newS_8
        lP = ''
        for z in range(32): lP += pPrepare[pBox[z] - 1]
        tempR = rBlock[i]
        rforXOR = ''
        for f in tempR: rforXOR += str(f)
        finalL = str(bin(int(rforXOR, 2) ^ int(lP, 2)))[2:].zfill(32)
        NewL = []
        for v in finalL: NewL.append(int(v))
        lBlock.append(NewL)
    cryptL = ''
    cryptR = ''
    for i in lBlock[16]: cryptL += str(i)

    for i in rBlock[16]: cryptR += str(i)

    cryptBeforeIPR = cryptL + cryptR
    finalCrypt = ''
    for i in range(64): finalCrypt += cryptBeforeIPR[ipr[i] - 1]

    return translate(finalCrypt, 'b', 's'), rBlock, lBlock

def encrypt(key):
    if len(e1.get()) == 8:
        inputData = translate(e1.get(), 's', 'b')
    else:
        inputData = translate(e1.get(), 'h', 'b')
    inputPer = []
    rBlock = []
    lBlock = []
    for i in range(64): inputPer.append(int(inputData[ip[i] - 1]))
    l0 = inputPer[:32]
    r0 = inputPer[32:]
    rBlock.append(r0)
    lBlock.append(l0)
    for i in range(16):
        e = ''
        temp_r = rBlock[i]
        lBlock.append(rBlock[i])
        for q in range(32): e += str(temp_r[eBox[q] - 1])
        ek = str(bin(int(e, 2) ^ int(key[i], 2)))[2:].zfill(48)
        eks = [ek[w:w + 6] for w in range(0, 48, 6)]
        s1 = eks[0]
        s2 = eks[1]
        s3 = eks[2]
        s4 = eks[3]
        s5 = eks[4]
        s6 = eks[5]
        s7 = eks[6]
        s8 = eks[7]
        s1_x = int((s1[0] + s1[5]), 2)
        s1_y = int((s1[1] + s1[2] + s1[3] + s1[4]), 2)

        s2_x = int((s2[0] + s2[5]), 2)
        s2_y = int((s2[1] + s2[2] + s2[3] + s2[4]), 2)

        s3_x = int((s3[0] + s3[5]), 2)
        s3_y = int((s3[1] + s3[2] + s3[3] + s3[4]), 2)

        s4_x = int((s4[0] + s4[5]), 2)
        s4_y = int((s4[1] + s4[2] + s4[3] + s4[4]), 2)

        s5_x = int((s5[0] + s5[5]), 2)
        s5_y = int((s5[1] + s5[2] + s5[3] + s5[4]), 2)

        s6_x = int((s6[0] + s6[5]), 2)
        s6_y = int((s6[1] + s6[2] + s6[3] + s6[4]), 2)

        s7_x = int((s7[0] + s7[5]), 2)
        s7_y = int((s7[1] + s7[2] + s7[3] + s7[4]), 2)

        s8_x = int((s8[0] + s8[5]), 2)
        s8_y = int((s8[1] + s8[2] + s8[3] + s8[4]), 2)

        newS_1 = str(bin(sb1[s1_x][s1_y]))[2:].zfill(4)
        newS_2 = str(bin(sb2[s2_x][s2_y]))[2:].zfill(4)
        newS_3 = str(bin(sb3[s3_x][s3_y]))[2:].zfill(4)
        newS_4 = str(bin(sb4[s4_x][s4_y]))[2:].zfill(4)
        newS_5 = str(bin(sb5[s5_x][s5_y]))[2:].zfill(4)
        newS_6 = str(bin(sb6[s6_x][s6_y]))[2:].zfill(4)
        newS_7 = str(bin(sb7[s7_x][s7_y]))[2:].zfill(4)
        newS_8 = str(bin(sb8[s8_x][s8_y]))[2:].zfill(4)
        pPrepare = newS_1 + newS_2 + newS_3 + newS_4 + newS_5 + newS_6 + newS_7 + newS_8
        rP = ''
        for z in range(32): rP += pPrepare[pBox[z] - 1]
        tempL = lBlock[i]
        lforXOR = ''
        for f in tempL: lforXOR += str(f)
        finalR = str(bin(int(lforXOR, 2) ^ int(rP, 2)))[2:].zfill(32)
        NewR = []
        for v in finalR: NewR.append(int(v))
        rBlock.append(NewR)
    cryptL = ''
    cryptR = ''
    for i in lBlock[16]: cryptL += str(i)

    for i in rBlock[16]: cryptR += str(i)

    cryptBeforeIPR = cryptR + cryptL
    finalCrypt = ''
    for i in range(64): finalCrypt += cryptBeforeIPR[ipr[i] - 1]
    if len(e1.get()) == 8:
        return translate(finalCrypt, 'b', 'h'), rBlock, lBlock
    else:
        return translate(finalCrypt, 'b', 's'), rBlock, lBlock

def round_info():
    if int(round_text.get()) <16:
        if r2_var.get() == 1:

            keyArray_enc = keyPrepare()
            encryptText, re, le = encrypt(keyArray_enc)
            le.pop(0)
            re.pop(0)

            l_b_text.delete(0, END)
            r_b_text.delete(0, END)
            round_key.delete(0, END)
            temp_counter = int(round_text.get())
            lb1 = ''
            rb1 = ''
            for i in le[temp_counter]: lb1+=str(i)
            for i in re[temp_counter]: rb1+=str(i)
            l_b_text.insert(0, lb1)
            r_b_text.insert(0, rb1)
            round_key.insert(0, keyArray_enc[temp_counter])
            round_text.delete(0, END)
            round_text.insert(0, str(temp_counter+1))
        elif r2_var.get() == 2:

            keyArray = keyPrepare()
            keyArrayRevers = list(reversed(keyArray))
            decryptText, rd, ld = decrypt(keyArrayRevers)
            ld.pop(0)
            rd.pop(0)

            l_b_text.delete(0, END)
            r_b_text.delete(0, END)
            round_key.delete(0, END)
            temp_counter = int(round_text.get())
            lb2 = ''
            rb2 = ''
            for i in ld[temp_counter]: lb2+=str(i)
            for i in rd[temp_counter]: rb2+=str(i)
            l_b_text.insert(0, lb2)
            r_b_text.insert(0, rb2)
            round_key.insert(0, keyArrayRevers[temp_counter])
            round_text.delete(0, END)
            round_text.insert(0, str(temp_counter+1))
        else:
            mb.showerror('Ошибка', message = 'Не выбран тип шифрования')
    else:
        round_text.delete(0, END)
        round_text.insert(0, '0')
        l_b_text.delete(0, END)
        r_b_text.delete(0, END)
        round_key.delete(0, END)

#########################_____таблицы_____###########################

ip = [58, 50, 42, 34, 26, 18, 10, 2, \
      60, 52, 44, 36, 28, 20, 12, 4, \
      62, 54, 46, 38, 30, 22, 14, 6, \
      64, 56, 48, 40, 32, 24, 16, 8, \
      57, 49, 41, 33, 25, 17, 9, 1, \
      59, 51, 43, 35, 27, 19, 11, 3, \
      61, 53, 45, 37, 29, 21, 13, 5, \
      63, 55, 47, 39, 31, 23, 15, 7]

ipr = [40, 8, 48, 16, 56, 24, 64, 32, \
       39, 7, 47, 15, 55, 23, 63, 31, \
       38, 6, 46, 14, 54, 22, 62, 30, \
       37, 5, 45, 13, 53, 21, 61, 29, \
       36, 4, 44, 12, 52, 20, 60, 28, \
       35, 3, 43, 11, 51, 19, 59, 27, \
       34, 2, 42, 10, 50, 18, 58, 26, \
       33, 1, 41, 9, 49, 17, 57, 25]

eBox = [32, 1, 2, 3, 4, 5, \
        4, 5, 6, 7, 8, 9, \
        8, 9, 10, 11, 12, 13, \
        12, 13, 14, 15, 16, 17, \
        16, 17, 18, 19, 20, 21, \
        20, 21, 22, 23, 24, 25, \
        24, 25, 26, 27, 28, 29, \
        28, 29, 30, 31, 32, 1]

pBox = [16, 7, 20, 21, 29, 12, 28, 17, \
        1, 15, 23, 26, 5, 18, 31, 10, \
        2, 8, 24, 14, 32, 27, 3, 9, \
        19, 13, 30, 6, 22, 11, 4, 25]

gBox = [57, 49, 41, 33, 25, 17, 9, \
        1, 58, 50, 42, 34, 26, 18, \
        10, 2, 59, 51, 43, 35, 27, \
        19, 11, 3, 60, 52, 44, 36, \
        63, 55, 47, 39, 31, 23, 15, \
        7, 62, 54, 46, 38, 30, 22, \
        14, 6, 61, 53, 45, 37, 29, \
        21, 13, 5, 28, 20, 12, 4]

hBox = [14, 17, 11, 24, 1, 5, 3, 28, \
        15, 6, 21, 10, 23, 19, 12, 4, \
        26, 8, 16, 7, 27, 20, 13, 2, \
        41, 52, 31, 37, 47, 55, 30, 40, \
        51, 45, 33, 48, 44, 49, 39, 56, \
        34, 53, 46, 42, 50, 36, 29, 32]

shiftBox = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

sb1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7], \
       [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8], \
       [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0], \
       [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

sb2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10], \
       [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5], \
       [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15], \
       [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

sb3 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8], \
       [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1], \
       [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7], \
       [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

sb4 = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15], \
       [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9], \
       [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4], \
       [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

sb5 = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9], \
       [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6], \
       [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14], \
       [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

sb6 = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11], \
       [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8], \
       [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6], \
       [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

sb7 = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1], \
       [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6], \
       [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2], \
       [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

sb8 = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7], \
       [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2], \
       [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8], \
       [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

###############################################################################
key_gen()
r2_var.trace('w', lambda *args: crypt())
root.mainloop()