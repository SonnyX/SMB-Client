namespace SMBLibrary.Authentication.GssApi
{
    public class GssContext
    {
        internal IGssMechanism Mechanism;
        internal object? MechanismContext;

        internal GssContext(IGssMechanism mechanism, object? mechanismContext)
        {
            Mechanism = mechanism;
            MechanismContext = mechanismContext;
        }
    }
}