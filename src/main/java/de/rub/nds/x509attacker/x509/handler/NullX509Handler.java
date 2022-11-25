package de.rub.nds.x509attacker.x509.handler;

import de.rub.nds.x509attacker.chooser.X509Chooser;
import de.rub.nds.x509attacker.x509.base.X509Component;

/**
 * This handler does not update anything. A lot of X509 components have no
 * reason to update the context.
 *
 * @param <Component>
 */
public class NullX509Handler<Component extends X509Component> extends X509Handler<Component> {

    public NullX509Handler(Component component, X509Chooser chooser) {
        super(component, chooser);
    }

    @Override
    public void adjustContext() {
    }

    @Override
    public void adjustRuntimeContext() {
    }

}
