using System;
using System.Reflection.Emit;

namespace KeeFarceDLL
{
    public class Converter<T>
    {
        delegate U Void2ObjectConverter<U>(IntPtr pManagedObject);
        static Void2ObjectConverter<T> myConverter;

        // The type initializer is run every time the converter is instantiated with a different 
        // generic argument. 
        static Converter()
        {
            GenerateDynamicMethod();
        }

        static void GenerateDynamicMethod()
        {
            if (myConverter == null)
            {
                Console.WriteLine("[KeeFarceDLL] Dynamic Method init");
                DynamicMethod method = new DynamicMethod("ConvertPtrToObjReference", typeof(T), new Type[] { typeof(IntPtr) }, typeof(IntPtr), true);
                var gen = method.GetILGenerator();
                // Load first argument 
                gen.Emit(OpCodes.Ldarg_0);
                // return it directly. The Clr will take care of the cast!
                // this construct is unverifiable so we need to plug this into an assembly with 
                // IL Verification disabled
                gen.Emit(OpCodes.Ret);
                myConverter = (Void2ObjectConverter<T>)method.CreateDelegate(typeof(Void2ObjectConverter<T>));
                Console.WriteLine("[KeeFarceDLL] init done");
            }
        }

        public T ConvertFromIntPtr(IntPtr pObj)
        {
            return myConverter(pObj);
        }
    }
}
